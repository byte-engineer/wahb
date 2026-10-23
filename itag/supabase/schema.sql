-- ITAG database schema for Supabase.
-- Run this once in Supabase: SQL Editor -> New query -> paste -> Run.
-- Safe to re-run: it only creates what is missing and replaces the functions.
--
-- Security model:
--   * Tables have row-level security ON and no policies, so the public API
--     cannot read or write them directly.
--   * Everything goes through the functions below. Passwords are checked on
--     the server (bcrypt), and the public only ever gets the fields the owner
--     marked as visible.

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------- tables

create table if not exists public.tags (
  code            text primary key,
  created_at      timestamptz not null default now(),
  registered_at   timestamptz,
  pw_hash         text,                              -- null = not registered yet
  fields          jsonb not null default '{}'::jsonb,
  visible         jsonb not null default '{}'::jsonb,
  failed_attempts int  not null default 0,
  locked_until    timestamptz
);

create table if not exists public.admins (
  email text primary key
);

alter table public.tags   enable row level security;
alter table public.admins enable row level security;
revoke all on public.tags, public.admins from anon, authenticated;

-- ---------------------------------------------------------------- helpers

create or replace function public._itag_keys() returns text[]
language sql immutable as $$
  select array['name','phone','email','ecName','ecPhone','blood','medical','notes']
$$;

-- Keep only known keys, as text, max 500 characters each.
create or replace function public._clean_fields(p jsonb) returns jsonb
language sql immutable as $$
  select coalesce(jsonb_object_agg(k, left(btrim(coalesce(p->>k, '')), 500)), '{}'::jsonb)
  from unnest(public._itag_keys()) k
$$;

-- Keep only known keys, as true/false.
create or replace function public._clean_visible(p jsonb) returns jsonb
language sql immutable as $$
  select coalesce(jsonb_object_agg(k, coalesce(p->k = 'true'::jsonb, false)), '{}'::jsonb)
  from unnest(public._itag_keys()) k
$$;

-- What a finder sees: visible, non-empty fields only.
create or replace function public._public_view(f jsonb, v jsonb) returns jsonb
language sql immutable as $$
  select coalesce(jsonb_object_agg(k, f->>k), '{}'::jsonb)
  from unnest(public._itag_keys()) k
  where coalesce(v->k = 'true'::jsonb, false) and coalesce(f->>k, '') <> ''
$$;

-- Checks a tag's password. Returns {"ok":true} or {"error":"wrong"|"locked"}.
-- Returns instead of raising so the failed-attempt counter is not rolled back.
-- After 5 wrong passwords the tag is locked for 15 minutes.
create or replace function public._owner_auth(p_code text, p_pw text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  r public.tags;
begin
  select * into r from public.tags where code = upper(btrim(p_code)) for update;
  if not found or r.pw_hash is null then
    return jsonb_build_object('error', 'wrong');
  end if;
  if r.locked_until is not null and r.locked_until > now() then
    return jsonb_build_object('error', 'locked');
  end if;
  if r.pw_hash <> crypt(coalesce(p_pw, ''), r.pw_hash) then
    update public.tags
       set failed_attempts = case when failed_attempts + 1 >= 5 then 0 else failed_attempts + 1 end,
           locked_until    = case when failed_attempts + 1 >= 5 then now() + interval '15 minutes' else locked_until end
     where code = r.code;
    return jsonb_build_object('error', case when r.failed_attempts + 1 >= 5 then 'locked' else 'wrong' end);
  end if;
  update public.tags set failed_attempts = 0, locked_until = null where code = r.code;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public._is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.admins
    where lower(email) = lower(coalesce(auth.jwt()->>'email', ''))
  )
$$;

-- ---------------------------------------------------------------- public API (finders and owners)

-- {"status":"not_found"} | {"status":"unregistered"} | {"status":"registered","public":{...}}
create or replace function public.get_tag(p_code text) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
declare
  r public.tags;
begin
  select * into r from public.tags where code = upper(btrim(p_code));
  if not found then
    return jsonb_build_object('status', 'not_found');
  end if;
  if r.pw_hash is null then
    return jsonb_build_object('status', 'unregistered');
  end if;
  return jsonb_build_object('status', 'registered', 'public', public._public_view(r.fields, r.visible));
end $$;

-- First scan: claim an unregistered tag.
create or replace function public.register_tag(p_code text, p_pw text, p_fields jsonb, p_visible jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  r public.tags;
  f jsonb := public._clean_fields(p_fields);
begin
  select * into r from public.tags where code = upper(btrim(p_code)) for update;
  if not found then
    return jsonb_build_object('error', 'not_found');
  end if;
  if r.pw_hash is not null then
    return jsonb_build_object('error', 'taken');
  end if;
  if coalesce(length(p_pw), 0) < 6 or length(p_pw) > 200 then
    return jsonb_build_object('error', 'short');
  end if;
  if f->>'name' = '' then
    return jsonb_build_object('error', 'req');
  end if;
  update public.tags
     set pw_hash = crypt(p_pw, gen_salt('bf')),
         fields = f,
         visible = public._clean_visible(p_visible),
         registered_at = now(),
         failed_attempts = 0,
         locked_until = null
   where code = r.code;
  return jsonb_build_object('ok', true);
end $$;

-- Owner login: returns everything, including private fields.
create or replace function public.owner_get(p_code text, p_pw text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  a jsonb := public._owner_auth(p_code, p_pw);
  r public.tags;
begin
  if a ? 'error' then
    return a;
  end if;
  select * into r from public.tags where code = upper(btrim(p_code));
  return jsonb_build_object('ok', true, 'fields', r.fields, 'visible', r.visible);
end $$;

create or replace function public.owner_update(p_code text, p_pw text, p_fields jsonb, p_visible jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  a jsonb := public._owner_auth(p_code, p_pw);
  f jsonb := public._clean_fields(p_fields);
begin
  if a ? 'error' then
    return a;
  end if;
  if f->>'name' = '' then
    return jsonb_build_object('error', 'req');
  end if;
  update public.tags
     set fields = f, visible = public._clean_visible(p_visible)
   where code = upper(btrim(p_code));
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------- admin API (logged-in admin only)

-- Creates n new tags with random codes like ITAG-7K3QX9MP.
-- The alphabet leaves out look-alike characters (0/O, 1/I/L).
create or replace function public.admin_create_tags(p_n int) returns text[]
language plpgsql security definer set search_path = public, extensions as $$
declare
  alphabet constant text := '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
  codes text[] := '{}';
  b bytea;
  c text;
begin
  if not public._is_admin() then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  if p_n is null or p_n < 1 or p_n > 500 then
    raise exception 'count must be between 1 and 500';
  end if;
  for i in 1..p_n loop
    loop
      b := gen_random_bytes(8);
      c := 'ITAG-';
      for j in 0..7 loop
        c := c || substr(alphabet, 1 + get_byte(b, j) % length(alphabet), 1);
      end loop;
      begin
        insert into public.tags (code) values (c);
        exit;
      exception when unique_violation then
        -- extremely unlikely; try another code
      end;
    end loop;
    codes := codes || c;
  end loop;
  return codes;
end $$;

-- No personal data here, only status.
create or replace function public.admin_list_tags()
returns table (code text, created_at timestamptz, registered_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not public._is_admin() then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  return query
    select t.code, t.created_at, t.registered_at
    from public.tags t
    order by t.created_at desc, t.code;
end $$;

-- For an owner who forgot their password: wipes the tag so it can be registered again.
create or replace function public.admin_reset_tag(p_code text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public._is_admin() then
    raise exception 'not_admin' using errcode = '42501';
  end if;
  update public.tags
     set pw_hash = null, fields = '{}', visible = '{}', registered_at = null,
         failed_attempts = 0, locked_until = null
   where code = upper(btrim(p_code));
end $$;

-- ---------------------------------------------------------------- permissions
-- Supabase lets anon/authenticated run new functions by default, so revoke
-- everything first, then grant only what each role needs.

revoke execute on function
  public._itag_keys(),
  public._clean_fields(jsonb),
  public._clean_visible(jsonb),
  public._public_view(jsonb, jsonb),
  public._owner_auth(text, text),
  public._is_admin(),
  public.get_tag(text),
  public.register_tag(text, text, jsonb, jsonb),
  public.owner_get(text, text),
  public.owner_update(text, text, jsonb, jsonb),
  public.admin_create_tags(int),
  public.admin_list_tags(),
  public.admin_reset_tag(text)
from public, anon, authenticated;

grant execute on function
  public.get_tag(text),
  public.register_tag(text, text, jsonb, jsonb),
  public.owner_get(text, text),
  public.owner_update(text, text, jsonb, jsonb)
to anon, authenticated;

grant execute on function
  public.admin_create_tags(int),
  public.admin_list_tags(),
  public.admin_reset_tag(text)
to authenticated;
