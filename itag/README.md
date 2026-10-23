# ITAG

ITAG is a lost-and-found QR tag. Stick a label on an item. Whoever finds it scans the QR code and sees the contact and emergency details the owner chose to share.

- `index.html` is the public site, for finders and owners.
- `admin.html` lets you create tag codes and print QR labels.
- `config.js` holds your Supabase project details.
- `supabase/schema.sql` sets up the database (run it once).

The site is hosted for free on **GitHub Pages**, and the data lives in **Supabase** (free plan).

## How it works

1. **You (admin)** create tags in `admin.html`. Each gets a random code like `ITAG-7K3QX9MP`. Print the QR labels and stick them on items.
2. **The owner** scans a new label and fills in their details. They tick which fields strangers may see, and set a password.
3. **A finder** scans the label and sees only the visible fields, plus a "Call" button if the emergency phone is shared.
4. **The owner** can log in later with the tag code and password to change their details.

Made-up codes show "Tag not found". Only tags you created can be registered.

## Setup

### 1. Supabase (database)
1. Create a free account at <https://supabase.com> and a **New project**. Save the database password it asks for somewhere safe.
2. Open **SQL Editor → New query**, paste all of `supabase/schema.sql` and click **Run**.
3. Create your admin login:
   - Go to **Authentication → Users → Add user → Create new user**.
   - Enter your email and a strong password, and tick "Auto confirm user".
   - Back in **SQL Editor**, run:
     ```sql
     insert into admins (email) values ('your-email@example.com');
     ```
4. In **Project Settings → API Keys**, copy:
   - the **Project URL**
   - the **publishable** key (or the legacy **anon** key)

   Never copy the *secret* or *service_role* key into this project.

### 2. GitHub Pages (hosting)
1. Create a new **public** repository on GitHub named `itag`.
2. Upload the contents of this folder (`index.html`, `admin.html`, `config.js`, `README.md`, `supabase/`).
3. In the repo, go to **Settings → Pages → Build and deployment**. Choose *Deploy from a branch*, then *main* / *(root)*, and save.
4. After a minute your site is at `https://YOUR-GITHUB-NAME.github.io/itag/`.

### 3. Fill in `config.js`
Edit it on GitHub or locally and push the change:
```js
window.ITAG_CONFIG = {
  SUPABASE_URL: "https://abcdefgh.supabase.co",
  SUPABASE_ANON_KEY: "sb_publishable_...",
  SITE_URL: "https://YOUR-GITHUB-NAME.github.io/itag/"
};
```

### 4. Make tags
1. Open `https://YOUR-GITHUB-NAME.github.io/itag/admin.html` and log in.
2. Create some tags and click **Print**. Print on sticker paper, or print and laminate.

## Testing on your computer
To test before publishing, run this from this folder:
```
python -m http.server 8000
```
Then open <http://localhost:8000/admin.html>. To test QR links locally, temporarily set `SITE_URL` to `http://localhost:8000/`. Set it back before printing real labels.

## Notes
- **The publishable/anon key in `config.js` is meant to be public.** The database only allows the actions defined in `schema.sql`.
- **Forgotten owner password:** in `admin.html`, click **Reset** next to the tag. This erases the owner's info so they can register the tag again.
- **Brute-force protection:** after 5 wrong passwords, owner login for that tag is locked for 15 minutes.
- **Free-plan pausing:** Supabase pauses free projects after about a week with no activity. Restart it from the dashboard, or upgrade once you have real users.
