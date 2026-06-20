# DirectChat Web

This repository is the DirectChat web app plus Render relay deployment.

The page reads `relay-config.json` at runtime, so the stable website URL can stay the same while the active relay URL changes.

Current Render URL:

```text
https://directchat-relay.onrender.com/
```

Current relay:

```text
https://directchat-relay.onrender.com/
```

Legacy Cloudflare Pages URL:

```text
https://directchat-web.pages.dev/
```

Expected GitHub Pages URL after the remote repo exists:

```text
https://leonardzyxu-ui.github.io/DirectChat-Web/
```

## Render Web Service

Render should use:

```sh
Build Command: npm install
Start Command: npm start
```

Required environment variables:

```text
DIRECTCHAT_STATIC_ROOT=.
UPSTASH_REDIS_REST_URL=<from Upstash>
UPSTASH_REDIS_REST_TOKEN=<from Upstash>
VAPID_PUBLIC_KEY=<optional web push public key>
VAPID_PRIVATE_KEY=<optional web push private key>
VAPID_SUBJECT=mailto:you@example.com
```

## Refresh From The App Build

From the parent `developer` folder:

```sh
cd DirectChatRelay
npm run build
rsync -a --delete web/dist/ ../DirectChatWeb/ --exclude .git
cd ../DirectChatWeb
git add .
git commit -m "Update DirectChat web build"
git push
```
