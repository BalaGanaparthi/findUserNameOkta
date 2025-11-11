# Okta Account Recovery App (Netlify Deployment)

This guide explains how to deploy the application to Netlify. This method uses Netlify's static file CDN for the index.html frontend and Netlify Serverless Functions for the Go backend.

This process does not use Docker.

## Prerequisites

- A [Netlify](https://www.netlify.com/) account.

- A [GitHub](https://github.com/), [GitLab](https://gitlab.com/), or [Bitbucket](https://bitbucket.org/) account.

Deployment Steps

### 1. Project Setup (You've done this)

Ensure your project is structured correctly:

- index.html is in the root.

- netlify.toml is in the root.

- Your Go backend is at netlify/functions/api/main.go.

- Your go.mod and go.sum are in the root and updated.

### 2. Push to GitHub

Create a new repository on GitHub (or your preferred Git provider) and push your project:

```bash
# Make sure to add the new files
git add index.html netlify.toml go.mod go.sum netlify/functions/api/main.go
git commit -m "Refactor for Netlify serverless deployment"
git push origin main
```

### 3. Create a New Site on Netlify

Log in to your Netlify account.

From the "Sites" overview, click "Add new site" -> "Import an existing project".

Connect to your Git provider (GitHub, etc.).

Find and select your new repository.

### 4. Configure Build Settings

Netlify should automatically detect your netlify.toml file. The settings should look like this:

Build command: go mod tidy (or can be left blank, netlify.toml handles it)

Publish directory: . (or can be left blank, netlify.toml handles it)

Functions directory: netlify/functions

If it doesn't auto-populate, you can set them. Click "Deploy site".

### 5. Add Environment Variables (CRITICAL)

Your site will fail its first deploy because it's missing the secret keys.

After the site is created, go to its dashboard.

Click on "Site configuration" (or "Site settings").

Go to "Build & deploy" -> "Environment".

Click "Edit variables" and add the following, using the exact same values from your local .env file:

OKTA_DOMAIN

OKTA_API_TOKEN

COOKIE_HASH_KEY

COOKIE_BLOCK_KEY

GO_VERSION (Set this to 1.21)

IMPORTANT: Do not use quotes, just paste the raw values.

### 6. Redeploy

Go back to your site's "Deploys" tab.

Click "Trigger deploy" -> "Clear cache and deploy site".

Netlify will now re-build your site, compile your Go function, and inject your environment variables.

### 7. You're Live!

Once the deploy finishes, you can visit your public https://your-site-name.netlify.app URL. The Go backend is now running as a serverless function, and your frontend is served from a global CDN.

### 8. Checkin to Github

echo "# findUserNameOkta" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin git@github.com:BalaGanaparthi/findUserNameOkta.git
git push -u origin main
