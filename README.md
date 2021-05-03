# OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer

<!---
This document defines an application-level sender-constraint mechanism for
OAuth 2.0 access tokens and refresh tokens that can be applied when neither mTLS nor
OAuth Token Binding are utilized. It achieves proof-of-possession using
a public/private key pair.
--->
このドキュメントでは、mTLSもOAuthトークンバインディングも使用されていない場合に適用できる、OAuth2.0アクセストークンと更新トークンのアプリケーションレベルの送信者同定メカニズムを定義しています。  
公開鍵と秘密鍵のペアを使用して、所有の証明を実現します。  

<!---
Written in markdown for the [mmark processor](https://github.com/mmarkdown/mmark).
--->
[mmark processor](https://github.com/mmarkdown/mmark) 方言の markdown で書かれています。  

<!---
## Compiling
--->
## コンパイル方法 {#Compiling}

<!---
### using Docker
--->
### Dockerを使う方法 {#using-docker}

<!---
From the root of this repository, run
--->
このリポジトリのルートディレクトリで以下を実行してください。  

<!---
```bash
docker run -v `pwd`:/data danielfett/markdown2rfc main.md
```
--->
```bash
perl -ne '$l=$_;$o=1 if $l=~/^<!---/;print $l if !$o;$o=0 if $l=~/^--->/;' <main.md >main.ja.md
docker run -v `pwd`:/data danielfett/markdown2rfc main.ja.md
perl -pi -e 's/&amp;#/&#/g' main.ja.md
```
<!---
(see https://github.com/oauthstuff/markdown2rfc)
--->
(詳細は右のURIを見てください。 https://github.com/oauthstuff/markdown2rfc)

<!---
### without Docker
--->
### Dockerを使わない方法 {#without-docker}

<!---
compile using mmark and xml2rfc: `mmark main.md > draft.xml; xml2rfc --html draft.xml`
--->
このリポジトリのルートディレクトリで以下を実行してください。  
コンパイルには mmark と xml2rfc が必要です。  

```bash
go get github.com/mmarkdown/mmark
pip install --user xml2rfc

./make.sh
```
