# DirectChat Web

This repository is the static DirectChat web app deployment.

The page reads `relay-config.json` at runtime, so the stable website URL can stay the same while the active relay URL changes.

Current live URL:

```text
https://directchat-web.pages.dev/
```

Expected GitHub Pages URL after the remote repo exists:

```text
https://leonardzyxu-ui.github.io/DirectChat-Web/
```

Current relay:

```text
https://pool-associations-clone-jewellery.trycloudflare.com/
```

## Publish To GitHub

Create an empty public GitHub repository named `DirectChat-Web` under `leonardzyxu-ui`, then push this local repo:

```sh
git remote add origin https://github.com/leonardzyxu-ui/DirectChat-Web.git
git push -u origin main
```

The included `.github/workflows/pages.yml` workflow deploys the repository root to GitHub Pages.

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
