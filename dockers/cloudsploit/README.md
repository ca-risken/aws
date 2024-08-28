# CloudSploitのアップグレード手順

CloudSploitのバージョン固定方法を以下に示します。
ポイントは、CloudSploit自体のバージョン管理（コミットHash）と依存ライブラリのバージョン管理（lockファイル）です。

※ CloudSploitはJavascriptで動きますが、OSS側でlockファイルを管理してないためRISKEN側で動作確認済みのバージョンを管理・使用します。

1. アップデートしたいバージョンをメモする
https://github.com/aquasecurity/cloudsploit

2. ローカルでyarn.lockを生成する(`/tmp` ディレクトリで作業)
```shell
git clone https://github.com/aquasecurity/cloudsploit.git /tmp/cloudsploit
cd /tmp/cloudsploit
git checkout ${CLOUDSPLOIT_COMMIT_HASH}
yarn install
ls yarn.lock
```

3. Dockerfileを修正する（ `CLOUDSPLOIT_COMMIT_HASH` を更新）
4. yarn.lockをコピーする
5. コンテナをビルドして動作確認

動作確認ができたらコミットしてください。
