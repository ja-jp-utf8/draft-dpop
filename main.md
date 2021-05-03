%%%
title = "OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)"
abbrev = "OAuth DPoP"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-ietf-oauth-dpop-04"
stream = "IETF"
status = "standard"
    
[[author]]
initials="D."
surname="Fett"
fullname="Daniel Fett"
organization="yes.com"
    [author.address]
    email = "mail@danielfett.de"

[[author]]
initials="B."
surname="Campbell"
fullname="Brian Campbell"
organization="Ping Identity"
    [author.address]
    email = "bcampbell@pingidentity.com"

[[author]]
initials="J."
surname="Bradley"
fullname="John Bradley"
organization="Yubico"
    [author.address]
    email = "ve7jtb@ve7jtb.com"


[[author]]
initials="T."
surname="Lodderstedt"
fullname="Torsten Lodderstedt"
organization="yes.com"
    [author.address]
    email = "torsten@lodderstedt.net"

[[author]]
initials="M."
surname="Jones"
fullname="Michael Jones"
organization="Microsoft"
    [author.address]
    email = "mbj@microsoft.com"
    uri = "https://self-issued.info/"
    
    
[[author]]
initials="D."
surname="Waite"
fullname="David Waite"
organization="Ping Identity"
    [author.address]
    email = "david@alkaline-solutions.com"

%%%

<!---
.# Abstract 
--->

.# 概要 {#abstract}

<!---
This document describes a mechanism for sender-constraining OAuth 2.0
tokens via a proof-of-possession mechanism on the application level.
This mechanism allows for the detection of replay attacks with access and refresh
tokens.
--->

このドキュメントでは アプリケーション層の proof-of-possession (所有者証明) を通して行われる、 OAuth 2.0 トークンの送信者同定メカニズムについて説明します。  
このメカニズムにより、アクセストークンとリフレッシュトークンを用いたリプレイ攻撃の検出が可能になります。  

{mainmatter}


<!---
# Introduction {#Introduction}
--->
# はじめに {#Introduction}

<!---
DPoP, an abbreviation for Demonstrating Proof-of-Possession at the Application Layer,
is an application-level mechanism for
sender-constraining OAuth access and refresh tokens. It enables a client to
demonstrate proof-of-possession of a public/private key pair by including 
a `DPoP` header in an HTTP request. The value of the header is a JWT [@!RFC7519] that 
enables the authorization
server to bind issued tokens to the public part of a client's 
key pair. Recipients of such tokens are then able to verify the binding of the
token to the key pair that the client has demonstrated that it holds via
the `DPoP` header, thereby providing some assurance that the client presenting
the token also possesses the private key.
In other words, the legitimate presenter of the token is constrained to be
the sender that holds and can prove possession of the private part of the
key pair.    
--->
DPoP は Demonstrating Proof-of-Possession at the Application Layer の略語であり、OAuthアクセストークンとOAuthリフレッシュトークンの送信者を同定するためのメカニズムです。  
DPoP は HTTP クライアントに対して DPoP ヘッダを用いて、公開鍵／秘密鍵のキーペアの保有者であること示すことを可能にします。  
DPoP ヘッダは JWT [@!RFC7519] 構造をしており、認可サーバで発行されたトークンとクライアントの持つキーペアを紐づけることを可能にします。  
これらのトークンの受信者は、トークンとキーペアが紐づいていること、クライアントが秘密鍵を保有していることを検証可能になります。  
言い換えれば、送信者が秘密鍵を保有を示すことにより、トークンの正当な所有者が送信者と同一であることを示すことができます。  

<!---
The mechanism described herein can be used in cases where other
methods of sender-constraining tokens that utilize elements of the underlying
secure transport layer, such as [@RFC8705] or [@I-D.ietf-oauth-token-binding],
are not available or desirable. For example, due to a sub-par user experience 
of TLS client authentication in user agents and a lack of support for HTTP token
binding, neither mechanism can be used if an OAuth client is a Single Page
Application (SPA) running in a web browser. Native applications installed
and run on a user's device, which often have dedicated protected storage
for cryptographic keys are another example well positioned to benefit
from DPoP-bound tokens to guard against misuse of tokens by a compromised
or malicious resource.
--->
DPoP は アプリケーション層の下層であるセキュアトランスポート層での送信者制限メカニズム ([@RFC8705] や [@I-D.ietf-oauth-token-binding] など) が有効でないか望ましくない場合に、記名式トークンの手段として利用できます。  
たとえば、ユーザエージェント上でTLSクライアント認証 (MTLS) のユーザ体験が好ましくない場合やトークンバインディング (OAUTB) がサポートされていない場合がこれに該当します。  
(OAuth クライアントが ブラウザ上で実行されるシングルページアプリケーション (SPA)の場合は、どちらのメカニズムも利用できません)   
ユーザーのデバイスにインストールされて実行されるネイティブアプリケーションは、暗号化キー専用の保護されたストレージを備えていることが多く、侵害されたリソースや悪意のあるリソースによるトークンの誤用を防ぐために、DPoPによって公開鍵に紐づけられたトークンの恩恵を受けるのに適した例です。  

<!---
DPoP can be used to sender-constrain access tokens regardless of the 
client authentication method employed. Furthermore, DPoP can
also be used to sender-constrain refresh tokens issued to public clients 
(those without authentication credentials associated with the `client_id`).
--->
DPoPは、クライアントの認証方法に関わらず、記名式アクセストークンとして使用することができます。  
さらに、DPoPを使用して、パブリッククライアント ( `client_id` に関連付けられた認証資格情報の秘密を保てないクライアント) に発行された記名式リフレッシュトークンとして使用することもできます。  

<!---
## Conventions and Terminology
--->
## 表記法と用語 {#keyword}

<!---
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@RFC2119] [@RFC8174] when, and only when, they
appear in all capitals, as shown here.
--->
このドキュメントのキーワードである「MUST」、「MUST NOT」、「REQUIRED」、「SHALL」、「SHALL NOT」、「SHOULD」、「SHOULD NOT」、「RECOMMENDED」、「NOT RECOMMENDED」、「MAY」、「OPTIONAL」は、ここに示すように、すべて大文字で表示される場合にのみ、BCP 14 [@RFC2119] [@RFC8174]で説明されているように解釈してください。  

<!---
This specification uses the terms "access token", "refresh token",
"authorization server", "resource server", "authorization endpoint",
"authorization request", "authorization response", "token endpoint",
"grant type", "access token request", "access token response", and
"client" defined by The OAuth 2.0 Authorization Framework [@!RFC6749].
--->
この仕様では、「アクセストークン:access token」、「リフレッシュトークン:refresh token」、「認可サーバー:authorization server」、「リソースサーバー:resource server」、「認可エンドポイント:authorization endpoint」、「認可リクエスト:authorization request」、「認可レスポンス:authorization response」、「トークンエンドポイント:token endpoint」、「グラントタイプ:grant type」、 「アクセストークンリクエスト:access token request」、「アクセストークンレスポンス:access token response」、「クライアント:client」はOAuth 2.0認証フレームワーク[@!RFC6749]によって定義された単語を固有名詞的に使用しています。  

<!---
# Objectives {#objective}
--->
# 目的 {#objective}

<!---
The primary aim of DPoP is to prevent unauthorized or illegitimate 
parties from using leaked or stolen access tokens by binding a token
to a public key upon issuance and requiring that the client demonstrate
possession of the corresponding private key when using the token. 
This constrains the legitimate sender of the token to only the party with
access to the private key and gives the server receiving the token added 
assurances that the sender is legitimately authorized to use it.  
--->
DPoPの主な目的は、発行時にトークンを公開鍵に紐づけ、トークンを使用するときにクライアントが対応する秘密鍵を所有していることを示すことを要求することにより、越権的な当事者または不正な当事者が漏洩または窃取されたアクセストークンを使用するのを防ぐことです。  
これにより、トークンを受信するサーバーは、トークンの正当な送信者が秘密鍵にアクセスできる当事者のみに制限し、送信者がトークンの使用を正当に認可されているという保証を得ることができます。  

<!---
Access tokens that are sender-constrained via DPoP thus stand in 
contrast to the typical bearer token, which can be used by any party in
possession of such a token. Although protections generally exist to 
prevent unintended disclosure of bearer tokens, unforeseen vectors for 
leakage have occurred due to vulnerabilities and implementation issues
in other layers in the protocol or software stack (CRIME, BREACH,
Heartbleed, and the Cloudflare parser bug are some examples). 
There have also been numerous published token theft attacks on OAuth 
implementations themselves. DPoP provides a general defense in depth 
against the impact of unanticipated token leakage. DPoP is not, however, 
a substitute for a secure transport and MUST always be used in 
conjunction with HTTPS. 
--->
したがって、DPoPで送信者を同定できるアクセストークンは、トークンを所有しているすべての関係者が使用してしまえる一般的なベアラートークンとは対照的です。  
ベアラトークンには既に漏洩を防ぐための保護機構が存在しますが、プロトコルまたはソフトウェアスタックの他の層 (CRIME、BREACH、Heartbleed、Cloudflareパーサーのバグなど) の脆弱性と実装の問題により、予期しない漏洩が発生しています。  
また、OAuth実装自体に対するトークン盗難攻撃の手法も数多く公開されています。  
DPoPは、予期しないトークンの漏洩の影響に対して広く利用できる多層防御の仕組みを提供します。  
ただし、DPoPは安全なトランスポートの代わりにはならず、常にHTTPSと組み合わせて使用する必要があります。 (**MUST**)

<!---
The very nature of the typical OAuth protocol interaction
necessitates that the client disclose the access token to the 
protected resources that it accesses. The attacker model 
in [@I-D.ietf-oauth-security-topics] describes cases where a 
protected resource might be counterfeit, malicious or compromised 
and play received tokens against other protected resources to gain
unauthorized access. Properly audience restricting access tokens can
prevent such misuse, however, doing so in practice has proven to be 
prohibitively cumbersome (even despite extensions such as [@RFC8707])
for many deployments.
Sender-constraining access tokens is a more robust and straightforward
mechanism to prevent such token replay at a different endpoint and DPoP 
is an accessible application layer means of doing so.
--->
典型的なOAuthプロトコルの処理フローでは、クライアントが保護されたリソースにアクセスする際に、アクセストークンを提示することを必要としています。  
[@I-D.ietf-oauth-security-topics]の攻撃者モデルは、保護されたリソースが偽造されたり、悪意を持って使用されたり、侵害されたり、受信したトークンを他の保護されたリソースへのアクセスに越権的に使用したりといった、不正なアクセス権を取得する可能性がある場合を説明しています。  
オーディエンスプロパティを適切に制限したアクセストークンではこのような悪用を防ぐことができますが、[@RFC8707]などの拡張機能があるにもかかわらず、実際には多くの環境下で対応が非常に困難であると論じられています。  
記名式アクセストークンは、別のエンドポイントでのそのようなトークンの不正な再利用を防ぐためのより堅牢で直接的なメカニズムであり、DPoPは、アプリケーション層で利用できるその一つの手段です。  

<!---
Due to the potential for cross-site scripting (XSS), browser-based 
OAuth clients bring to bear added considerations with respect to protecting 
tokens. The most straightforward XSS-based attack is for an attacker to
exfiltrate a token and use it themselves completely independent from the 
legitimate client. A stolen access token is used for protected
resource access and a stolen refresh token for obtaining new access tokens. 
If the private key is non-extractable (as is possible with [@W3C.WebCryptoAPI]),
DPoP renders exfiltrated tokens alone unusable. 
--->
クロスサイトスクリプティング (XSS) 攻撃を受ける可能性があるため、ブラウザーベースのOAuthクライアントでは、トークンの保護に関して追加の考慮事項が存在します。  
XSSベースの攻撃で、最も単純な被害は攻撃者がトークンを盗み出し、正当なクライアントから完全に独立して使用されてしまうことです。  
盗まれたアクセストークンは保護されたリソースへのアクセスに使用され、盗まれたリフレッシュトークンは新しいアクセストークンを取得するために使用されます。  
秘密鍵が盗み出せない場合 ([@W3C.WebCryptoAPI]で可能) 、DPoPは盗み出されたトークンだけを使用できなくします。  

<!---
XXS vulnerabilities also allow an attacker to execute code in the context of
the browser-based client application and maliciously use a token indirectly 
through the client. That execution context has access to utilize the signing 
key and thus can produce DPoP proofs to use in conjunction with the token. 
At this application layer there is most likely no feasible defense against
this threat except generally preventing XSS, therefore it is considered 
out of scope for DPoP.
--->
XSSの脆弱性がある場合、攻撃者はブラウザベースのクライアントアプリケーションのコンテキストでコードを実行することで、クライアントを介して間接的に悪意を持ってトークンを使用することもできます。  
そのコンテキストは、署名キーを利用するためのアクセス権を持っているため、トークンと組み合わせて使用するDPoP証明を生成できます。  
一般的にXSSを防止することを除いて、アプリケーション層ではこれらの脅威に対する実行可能な防御はほとんどないため、DPoPでは考慮外としています。  

<!---
Malicious XSS code executed in the context of the browser-based client application
is also in a position to create DPoP proofs with timestamp values in the future
and exfiltrate them in conjunction with a token. These stolen artifacts 
can later be used together independent of the client application to access
protected resources. The impact of such precomputed DPoP proofs is limited
somewhat by the proof being bound to an access token on protected resource access.
Because a proof covering an access token that don't yet exist cannot feasibly be created,
access tokens obtained with an exfiltrated refresh token and pre-computed proofs will be
unusable.
--->
ブラウザベースのクライアントアプリケーションのコンテキストで実行される悪意のあるXSSコードは、未来のタイムスタンプ値を使用してDPoP証明を作成し、トークンとともにそれらを窃取することもできます。  
これらの窃取された情報は、後にクライアントアプリケーションとは関係ないところで一緒に使用して、保護されたリソースにアクセスできてしまいます。  
このような事前生成されたDPoP証明の影響は、保護されたリソースアクセスの際のアクセストークンに紐づけられているDPoP証明によっていくらか制限が可能です。  
ちなみに、まだ存在していないアクセストークンに対するDPoP証明は生成できないため、窃取されたリフレッシュトークンと事前に計算されたDPoP証明で取得された新たなアクセストークンは悪用できません。  

<!---
Additional security considerations are discussed in (#Security).
--->
追加のセキュリティの考慮事項については、 (#Security) で説明しています。  

<!---
# Concept
--->
# コンセプト {#concept}

<!---
The main data structure introduced by this specification is a DPoP
proof JWT, described in detail below, which is sent as a header in an 
HTTP request. A client uses a DPoP proof JWT to prove
the possession of a private key corresponding to a certain public key.
Roughly speaking, a DPoP proof is a signature over a timestamp and some 
data of the HTTP request to which it is attached.
--->
この仕様で導入される主なデータ構造は、以下で詳細に説明するDPoP証明用のJWTであり、HTTPリクエストのヘッダーとして送信されます。  
クライアントは、DPoP証明用のJWTを使用して、特定の公開鍵に対応する秘密鍵の所有を証明します。  
大まかに言えば、DPoP証明は、タイムスタンプとそれが添付されているHTTPリクエストの一部のデータに対する署名です。  

!---
~~~ ascii-art
+--------+                                          +---------------+
|        |--(A)-- Token Request ------------------->|               |
| Client |        (DPoP Proof)                      | Authorization |
|        |                                          |     Server    |
|        |<-(B)-- DPoP-bound Access Token ----------|               |
|        |        (token_type=DPoP)                 +---------------+
|        |
|        | 
|        |                                          +---------------+
|        |--(C)-- DPoP-bound Access Token --------->|               |
|        |        (DPoP Proof)                      |    Resource   |
|        |                                          |     Server    |
|        |<-(D)-- Protected Resource ---------------|               |
|        |                                          +---------------+
+--------+
~~~
!---
<!---
Figure: Basic DPoP Flow {#basic-flow}
--->
Figure: 基本的なDPoPフロー {#basic-flow}

<!---
The basic steps of an OAuth flow with DPoP are shown in (#basic-flow):
--->
DPoPを使用したOAuthフローの基本的な手順 (#basic-flow):

<!---
  * (A) In the Token Request, the client sends an authorization grant 
    (e.g., an authorization code, refresh token, etc.)  
    to the authorization server in order to obtain an access token
    (and potentially a refresh token). The client attaches a DPoP
    proof to the request in an HTTP header.
  * (B) The authorization server binds (sender-constrains) the access token to the
    public key claimed by the client in the DPoP proof; that is, the access token cannot
    be used without proving possession of the respective private key.
    If a refresh token is issued to a public client, it too is
    bound to the public key of the DPoP proof. 
  * (C) To use the access token the client has to prove
    possession of the private key by, again, adding a header to the
    request that carries a DPoP proof for that request. The resource server needs to
    receive information about the public key to which the access token is bound. This
    information may be encoded directly into the access token (for
    JWT structured access tokens) or provided via token
    introspection endpoint (not shown). 
    The resource server verifies that the public key to which the
    access token is bound matches the public key of the DPoP proof.
  * (D) The resource server refuses to serve the request if the
    signature check fails or the data in the DPoP proof is wrong,
    e.g., the request URI does not match the URI claim in the DPoP
    proof JWT. The access token itself, of course, must also be 
    valid in all other respects. 
--->
  * (A) トークンリクエストでは、クライアントはアクセストークン  (および場合によってはリフレッシュトークン ) を取得するために、　認可情報  (たとえば、認可コード、リフレッシュトークンなど ) を認証サーバーに送信します。その際、クライアントはHTTPリクエストのヘッダーにDPoP証明を添付します。  
  * (B) 認可サーバーは、アクセストークンをDPoP証明を参照し、クライアントが提示した公開鍵に紐づけます  (記名します ) 。 つまり、アクセストークンは、それぞれの秘密鍵を所有していることを証明せずに使用することはできなくなります。 認可サーバーは、リフレッシュトークンがパブリッククライアントに発行された場合も、DPoP証明の公開鍵に紐づけます。  
  * (C) アクセストークンを使用するには、クライアントはDPoP証明を保持するヘッダーをHTTPリクエストに添付することにより、秘密鍵の所有を証明する必要があります。リソースサーバーは、アクセストークンが紐づけられている公開鍵に関する情報を受信する必要があります。この情報は、JWTで構造化アクセストークンの場合はアクセストークン内に直接エンコードできます。また、そうでない場合はトークンイントロスペクションエンドポイントを介して情報提供または検証します  (図には示されていません ) 。リソースサーバーはいずれかの方法で、アクセストークンが紐づけられている公開鍵がDPoP証明の公開鍵と一致することを確認します。  
  * (D) 署名チェックが失敗した場合、またはDPoP証明のデータが間違っている場合  (たとえば、リクエストURIがDPoP証明用のJWTのURIクレームと一致しない場合 ) 、リソースサーバーはリクエストの処理を拒否するように実装します。もちろん、アクセストークン自体も他のすべての点で有効であるか検証する必要があります。 

<!---
The DPoP mechanism presented herein is not a client authentication method.
In fact, a primary use case of DPoP is for public clients (e.g., single page
applications and native applications) that do not use client authentication. Nonetheless, DPoP
is designed such that it is compatible with `private_key_jwt` and all
other client authentication methods.
--->
ここで紹介するDPoP機構は、クライアント認証の手段ではありません。  
実際のところ、DPoPの主な使用例として挙げられるのは、クライアント認証を使用していないパブリッククライアント  (シングルページアプリケーションやネイティブアプリケーションなど ) です。  
それでも、DPoPは、 `private_key_jwt`および他のすべてのクライアント認証方法と互換性があるように設計されています。  

<!---
DPoP does not directly ensure message integrity but relies on the TLS
layer for that purpose. See (#Security) for details.
--->
DPoPはメッセージの整合性を直接保証しませんが、その目的のためにTLSレイヤーに依存します。 詳細については、 (#Security) を参照してください。  

<!---
# DPoP Proof JWTs {#the-proof}
--->
# DPoP証明用のJWT {#the-proof}

<!---
DPoP introduces the concept of a DPoP proof, which is a JWT created by
the client and sent with an HTTP request using the `DPoP` header field.
Each HTTP request requires a unique DPoP proof.
A valid DPoP proof demonstrates to the server that the client holds the private
key that was used to sign the  DPoP proof JWT. This enables authorization servers to bind
issued tokens to the corresponding public key (as described in (#access-token-request))
and for resource servers to verify the key-binding of tokens that
it receives (see (#http-auth-scheme)), which prevents said tokens from
being used by any entity that does not have access to the private key.
--->
DPoPは、クライアントによって生成され、 `DPoP`ヘッダーフィールドを使用してHTTPリクエストで送信されるJWTであるDPoP証明の概念を導入します。  
HTTPリクエストごとに、一意なDPoP証明を生成する必要があります。  
有効なDPoP証明は、クライアントがDPoP証明用のJWTの署名に使用された秘密鍵を保持していることをサーバーに示します。  
認可サーバーは発行されたトークンを対応する公開鍵に紐づけ ( (#access-token-request) で説明 ) 、リソースサーバーは受信したトークンと公開鍵の紐づけを検証します ( (#http-auth-scheme) を参照) 。  
これにより、秘密鍵にアクセスできないクライアントはトークンを使用できなくなります。  

<!---
The DPoP proof demonstrates possession of a key and, by itself, is not
an authentication or access control mechanism. When presented
in conjunction with a key-bound access token as described in (#http-auth-scheme),
the DPoP proof provides additional assurance about the legitimacy of the client
to present the access token. However, a valid DPoP proof JWT is not sufficient alone
to make access control decisions.
--->
DPoP証明は、秘密鍵の所持を示しており、それ自体は認証やアクセス制御のメカニズムではありません。  
DPoP証明は、(#http-auth-scheme) で説明されているように、公開鍵に紐づけられたアクセストークンと組み合わせて提示されることで、付加的にアクセストークンを提示しているクライアントに対する正当性の根拠を提供します。  
ただし、有効なDPoP証明用のJWTだけでは、アクセス制御の判断を行うのに十分ではありません。  

<!---
## The DPoP HTTP Header
--->
## DPoP HTTP ヘッダー {#dpop-header}

<!---
A DPoP proof is included in an HTTP request using the following message header field.
--->
DPoP証明は、HTTPリクエストの後述するメッセージヘッダーフィールドを使用します。  

<!---
`DPoP`
:   A JWT that adheres to the structure and syntax of (#DPoP-Proof-Syntax). 
--->
`DPoP`
:   JWTが遵守すべき構造と構文

<!---
(#dpop-proof-jwt) shows an example DPoP HTTP header field (line breaks 
and extra whitespace for display purposes only). 
--->
(#dpop-proof-jwt) は、DPoP HTTPヘッダーフィールドの例を示しています (例示を目的とした改行と余分な空白を含んでいます) 。  

!---
```
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj
 oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia
 WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg
 4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg
```
!---
<!---
Figure: Example `DPoP` header {#dpop-proof-jwt}
--->
Figure: `DPoP` ヘッダーの例 {#dpop-proof-jwt}

<!---
Note that per [@RFC7230] header field names are case-insensitive;
so `DPoP`, `DPOP`, `dpop`, etc., are all valid and equivalent header
field names. Case is significant in the header field value, however.  
--->
※ [@RFC7230] にある通り、HTTPヘッダの名称は大文字小文字の区別が無いことに注意してください。  
つまり、 `DPoP`、` DPOP`、 `dpop`などはすべて有効で同等のHTTPヘッダの名称です。  
ただし、HTTPヘッダの値では大文字と小文字の区別をします。  

<!---
## DPoP Proof JWT Syntax {#DPoP-Proof-Syntax}
--->
## DPoP証明用のJWTの構文 {#DPoP-Proof-Syntax}

<!---
A DPoP proof is a JWT ([@!RFC7519]) that is signed (using JWS,
[@!RFC7515]) with a private key chosen by the client (see below). The
header of a DPoP JWT contains at least the following parameters:
--->
DPoP証明は、クライアントが選択した秘密鍵を使用して (JWS [@!RFC7515]を使用して) 署名されたJWT [@!RFC7519] です (以下を参照)。  
DPoP JWTのヘッダーには、少なくとも次のパラメーターを含む必要があります:

<!---
 * `typ`: type header, value `dpop+jwt` (REQUIRED).
 * `alg`: a digital signature algorithm identifier as per [@!RFC7518]
   (REQUIRED). MUST NOT be `none` or an identifier for a symmetric
   algorithm (MAC).
 * `jwk`: representing the public key chosen by the client, in JWK
   format, as defined in Section 4.1.3 of [@!RFC7515] (REQUIRED).
   MUST NOT contain the private key.
--->
 * `typ`: 種類を示すヘッダー, `dpop+jwt` を指定します。(**REQUIRED**)  
 * `alg`: [@!RFC7518] によるデジタル署名アルゴリズムを指定します。(**REQUIRED**)  
   ただし、`none`や共通鍵暗号を示す識別子(MAC)であってはなりません。(**MUST NOT**)  
 * `jwk`: JWK([@!RFC7515]のセクション4.1.3で定義されている形式)で、クライアントが選択した公開鍵を指定します。(**REQUIRED**)  
   ただし、秘密鍵を含めてはなりません。(**MUST NOT**)  

<!---
The payload of a DPoP proof contains at least the following claims:
--->
DPoP証明のペイロードには、少なくとも次のクレームが含む必要があります。:

<!---
 * `jti`: Unique identifier for the DPoP proof JWT (REQUIRED).
   The value MUST be assigned such that there is a negligible 
   probability that the same value will be assigned to any 
   other DPoP proof used in the same context during the time window of validity.
   Such uniqueness can be accomplished by encoding (base64url or any other
   suitable encoding) at least 96 bits of
   pseudorandom data or by using a version 4 UUID string according to [@RFC4122].
   The `jti` can be used by the server for replay
   detection and prevention, see (#Token_Replay).
 * `htm`: The HTTP method for the request to which the JWT is
   attached, as defined in [@!RFC7231] (REQUIRED).
 * `htu`: The HTTP URI used for the request, without query and
   fragment parts (REQUIRED).
 * `iat`: Time at which the JWT was created (REQUIRED).
--->
 * `jti`: DPoP証明用のJWTの一意の識別子を指定します。 (**REQUIRED**)  
   有効期間中に同じコンテキストで使用される他のDPoP証明に同じ値が割り当てられる事が無いように、一意な値を割り当てる必要があります。(**MUST**)  
   このような一意性は、96ビット以上の疑似乱数データをエンコード (base64urlエンコードまたはその他の適切なエンコード) するか、[@RFC4122]に従ってバージョン4のUUID文字列を使用するなどの方法で実現できます。  
   サーバーは `jti`を使用して、リプレイ攻撃の検出と防止を行うことができます。(#Token_Replay) を参照してください。  
 * `htm`: [@!RFC7231]で定義されているものから、DPoPを使用するHTTPメソッドを指定します。(**REQUIRED**)  
 * `htu`: URIのうちクエリーとフラグメントを除いた部分を指定します。 (**REQUIRED**)  
 * `iat`: このJWTを生成した日時のUnixTimeStampを指定します。 (**REQUIRED**)  

<!---
When the DPoP proof is used in conjunction with the presentation of an access token, see 
(#protected-resource-access), the DPoP proof also contains the following claim:
--->
DPoP証明がアクセストークンと組み合わせて提示される場合 ( (#protected-resource-access) を参照) 、DPoP証明には次のクレームも含まれる必要があります。:

<!---
* `ath`: hash of the access token (REQUIRED).
   The value MUST be the result of a base64url encoding (with no padding) the SHA-256
   hash of the ASCII encoding of the associated access token's value.
--->
* `ath`: アクセストークンのハッシュ値を指定します。 (**REQUIRED**)  
   この値は、関連付けられたアクセストークン(ASCIIエンコーディング)のSHA-256ハッシュ (パディングなし) のbase64urlエンコーディングの結果の値である必要があります。(**MUST**)  

<!---
(#dpop-proof) is a conceptual example showing the decoded content of the DPoP 
proof in (#dpop-proof-jwt). The JSON of the JOSE header and payload are shown
but the signature part is omitted. As usual, line breaks and extra whitespace 
are included for formatting and readability.
--->
(#dpop-proof) は、(#dpop-proof-jwt) のDPoP証明の例です。  
※ 概念を示すためにデコードしています。  
※ JOSEヘッダーとペイロードのJSONが表示されますが、署名部分は省略されています。  
※ いつものように、フォーマットと読みやすさのために改行と余分な空白が含まれています。  

!---
```
{
  "typ":"dpop+jwt",
  "alg":"ES256",
  "jwk": {
    "kty":"EC",
    "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv":"P-256"
  }
}
.
{
  "jti":"-BwC3ESc6acc2lTc",
  "htm":"POST",
  "htu":"https://server.example.com/token",
  "iat":1562262616
}
```
!---
<!---
Figure: Example JWT content of a `DPoP` proof {#dpop-proof}
--->
Figure: `DPoP`証明用のJWTの例 {#dpop-proof}

<!---
Of the HTTP content in the request, only the HTTP method and URI are
included in the DPoP JWT, and therefore only these 2 headers of the request
are covered by the DPoP proof and its signature.
The idea is sign just enough of the HTTP data to
provide reasonable proof-of-possession with respect to the HTTP request. But 
that it be a minimal subset of the HTTP data so as to avoid the substantial 
difficulties inherent in attempting to normalize HTTP messages. 
Nonetheless, DPoP proofs can be extended to contain other information of the
HTTP request (see also (#request_integrity)).
--->
HTTPリクエストのうち、HTTPメソッドとURIのみがDPoP JWTには含まれているため、これら2つのヘッダーのみがDPoP証明とその署名で保証されます。  
これは、HTTPリクエストに合理的な所有者証明を実現するために必要十分なHTTPデータに署名するというアイデアに基づいています。  
また、HTTPメッセージの正規化を行う際に発生し得る固有の問題を回避するために、HTTPリクエストの最小限のサブセットである必要性も考慮されています。  
必要に応じて、DPoP証明を拡張することでHTTP要求の他の情報を含めることができます ( (#request_integrity) も参照) 。  

<!---
## Checking DPoP Proofs {#checking}
--->
## DPoP証明の検証 {#checking}

<!---
To check if a string that was received as part of an HTTP Request is a
valid DPoP proof, the receiving server MUST ensure that
--->
受信サーバーは、HTTPリクエストの一部として受信した文字列が以下の通りの手順に基づき、有効なDPoP証明であることを確認する必要があります。(**MUST**)  

<!---
 1. the string value is a well-formed JWT,
 1. all required claims per (#DPoP-Proof-Syntax) are contained in the JWT,
 1. the `typ` field in the header has the value `dpop+jwt`,
 1. the algorithm in the header of the JWT indicates an asymmetric digital
    signature algorithm, is not `none`, is supported by the
    application, and is deemed secure,
 1. the JWT signature verifies with the public key contained in the `jwk`
    header of the JWT,
 1. the `htm` claim matches the HTTP method value of the HTTP
    request in which the JWT was received,
 1. the `htu` claims matches the HTTPS URI value for the HTTP
    request in which the JWT was received, ignoring any query and
    fragment parts,
 1. the token was issued within an acceptable timeframe and,
    within a reasonable consideration of accuracy and resource utilization,
    a proof JWT with the same `jti` value has not previously been received at the same resource
    during that time period (see (#Token_Replay)).
--->
 1. 受信した文字列が正しいJWTであること
 1. (#DPoP-Proof-Syntax) にある必須クレームが全てJWTに含まれていること
 1. `typ` クレームの値が `dpop+jwt` であること
 1. `alg` クレームの値が共通鍵暗号アルゴリズムを示す値ではなく、`none` でもなく、危殆化されたアルゴリズムを示す値でもなく、アプリケーションでサポートされた値であること
 1. `jwk` クレームに含まれる公開鍵で、JWTの署名を検証し成功すること
 1. `htm` クレームの値が、JWTが受信されたHTTPリクエストのHTTPメソッドと一致すること
 1. `htu` クレームの値が、JWTが受信されたHTTPリクエストのURIのうちクエリとフラグメント以外の部分と一致すること
 1. トークンが許容可能な時間枠内に発行されており、同じ(精度とリソース使用率を合理的に考慮した時間範囲内で近い) `jti` クレームの値を持つJWT証明が同じリソースで以前に受信されていないこと ( (#Token_Replay) を参照)

<!---
Servers SHOULD employ Syntax-Based Normalization and Scheme-Based
Normalization in accordance with Section 6.2.2. and Section 6.2.3. of
[@!RFC3986] before comparing the `htu` claim.
--->
サーバーは、 `htu` クレームを比較する前に、[@!RFC3986]のセクション6.2.2およびセクション6.2.3に従って、構文ベースの正規化とスキームベースの正規化を実施する必要があります。(**SHOULD**)

<!---
If presented with an access token to a protected resource, the server MUST ensure
that the value of the `ath` claim equals the hash of the access token that has been
presented along side the DPoP proof.
--->

保護されたリソースへのアクセストークンが提示された場合、サーバーは `ath` クレームの値がDPoP証明とともに提示されたアクセストークンのハッシュと等しいことを確認する必要があります。(**MUST**)  

<!---
# DPoP Access Token Request {#access-token-request}
--->
# DPoPを用いたアクセストークンリクエスト {#access-token-request}

<!---
To request an access token that is bound to a public key using DPoP, the client MUST 
provide a valid DPoP proof JWT in a `DPoP` header when making an access token
request to the authorization server's token endpoint. This is applicable for all
access token requests regardless of grant type (including, for example,
the common `authorization_code` and `refresh_token` grant types but also extension grants
such as the JWT authorization grant [@RFC7523]). The HTTPS request shown in
(#token-request-code) illustrates such an access 
token request using an authorization code grant with a DPoP proof JWT
in the `DPoP` header (extra line breaks and whitespace for display purposes only).
--->
DPoPを使用して公開鍵に紐づけられたアクセストークンを要求する際、クライアントは承認サーバーのトークンエンドポイントにアクセストークンリクエストを行うときに、有効なDPoP証明用のJWTを `DPoP`ヘッダーに含める必要があります。(**MUST**)  
これは、タイプに関係なくすべてのタイプのアクセストークンリクエストに適用されます (たとえば、一般的な `authorization_code` および ` refresh_token` だけでなく、JWT認可フロー[@RFC7523]などの拡張付与も含まれます) 。  
(#token-request-code) は、 `DPoP`ヘッダーにDPoP証明用のJWTを含む認可コードフローを使用した場合のHTTPSによるアクセストークンリクエストを示しています (分かりやすさのため、余分な改行と空白を含んでいます) 。  

!---
~~~
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj
 oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia
 WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg
 4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg
 
grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
&code_verifier=bEaL42izcC-o-xBk0K2vuJ6U-y1p9r_wW2dFWIWgjz-
~~~
!---
<!---
Figure: Token Request for a DPoP sender-constrained token using an authorization code {#token-request-code}
--->
Figure: DPoPを使用したトークンリクエスト(認可コードフロー) {#token-request-code}

<!---
The `DPoP` HTTP header MUST contain a valid DPoP proof JWT.
If the DPoP proof is invalid, the authorization server issues an error 
response per Section 5.2 of [@RFC6749] with `invalid_dpop_proof` as the 
value of the `error` parameter. 
--->
`DPoP` HTTPヘッダーには、有効なDPoP証明用のJWTが含まれている必要があります。  
DPoP証明が無効な場合、許可サーバーは[@RFC6749]のセクション5.2に従って、 `error` パラメーターの値として` invalid_dpop_proof` を指定してエラーレスポンスを返却します。  

<!---
To sender-constrain the access token, after checking the validity of the
DPoP proof, the authorization server associates the issued access token with the
public key from the DPoP proof, which can be accomplished as described in (#Confirmation).
A `token_type` of `DPoP` in the access token
response signals to the client that the access token was bound to
its DPoP key and can be used as described in (#http-auth-scheme). 
The example response shown in (#token-response) illustrates such a 
response. 
--->
アクセストークンの送信者を限定するために、DPoP証明の有効性を確認した後、認可サーバーはアクセストークンをDPoP証明の公開鍵に紐づけた上で発行します。この流れは (#Confirmation) で説明しています。  
(#http-auth-scheme) のように、アクセストークンレスポンスの `DPoP` の ` token_type` は、アクセストークンがDPoP公開鍵に紐づけられていることをクライアントに通知するために使用できます。  
(#token-response) は、そのようなレスポンス例を示しています。  

!---
~~~
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
 "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
 "token_type": "DPoP",
 "expires_in": 2677,
 "refresh_token": "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g"
}
~~~
!---
<!---
Figure: Access Token Response {#token-response}
--->
Figure: アクセストークンレスポンス {#token-response}

<!---
The example response in (#token-response) included a refresh token, which the 
client can use to obtain a new access token when the previous one expires.
Refreshing an access token is a token request using the `refresh_token`
grant type made to the authorization server's token endpoint.  As with 
all access token requests, the client makes it a DPoP request by including 
a DPoP proof, which is shown in the (#token-request-rt) example
(extra line breaks and whitespace for display purposes only). 
--->
(#token-response) のレスポンス例には、更新トークンが含まれています。  
これを使用して、アクセストークンの有効期限が切れた際には、クライアントが新しいアクセストークンを取得できます。  
アクセストークンの更新は、認可サーバーのトークンエンドポイントに対して行われる `refresh_token` タイプを指定したトークンリクエストで行われます。
すべてのアクセストークンリクエストでも同様に、クライアントは (#token-request-rt) の例に倣って、DPoP証明を含めてリクエストを作成します (例示では、分かりやすさのために余分な改行と空白を含めています) 。

!---
~~~
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj
 oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia
 WF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5Qs
 GSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA

grant_type=refresh_token
&refresh_token=Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g

~~~
!---
<!---
Figure: Token Request for a DPoP-bound token using a refresh token {#token-request-rt}
--->
Figure: DPoPを使用したトークンリクエスト(リフレッシュトークン)  {#token-request-rt}

<!---
When an authorization server supporting DPoP issues a
refresh token to a public client that presents a valid DPoP proof at the
token endpoint, the refresh token MUST be bound
to the respective public key. The binding MUST be validated when the refresh
token is later presented to get new access tokens. As a result, such a client 
MUST present a DPoP proof for the same key that was used to obtain the refresh
token each time that refresh token is used to obtain a new access token. 
The implementation details of the binding of the refresh token are at the discretion of
the authorization server. The server both produces and
validates the refresh tokens that it issues so there's no interoperability
consideration in the specific details of the binding. 
--->
DPoPをサポートする認可サーバーは、トークンエンドポイントで有効なDPoP証明を提示するパブリッククライアントにリフレッシュトークンを発行する場合、リフレッシュトークンは指定された公開鍵に紐づける必要があります。(**MUST**)  
新しいアクセストークンを取得するためにリフレッシュトークンが提示された際には、公開鍵との紐づけを検証する必要があります。(**MUST**)  
その結果、そのようなクライアントは、新しいアクセストークンを取得するためにリフレッシュトークンが使用されるたびに、リフレッシュトークンを取得するために使用されたのと同じキーペアのDPoP証明を送信する必要があります。(**MUST**)  
リフレッシュトークンの紐づけ方法の実装の詳細は、認可サーバーの裁量に委ねられています。  
認可サーバーが発行するリフレッシュトークンの生成と検証の両方を行うため、紐づけ方法の仕様として相互運用性に関する考慮事項は定義されていません。  

<!---
An authorization server MAY elect to issue access tokens which are not DPoP bound,
which is signaled to the client with a value of `Bearer` in the `token_type` parameter 
of the access token response per [@RFC6750]. For a public client that is
also issued a refresh token, this has the effect of DPoP-binding the refresh token
alone, which can improve the security posture even when protected resources are not 
updated to support DPoP. 
--->
認可サーバーは、DPoPによって公開鍵に紐づけられてないアクセストークンを発行することを選択できます。(**MAY**)  
これは、[@RFC6750]によってアクセストークンレスポンスの `token_type` パラメータの値として ` Bearer` を指定することでクライアントに通知されます。  
リフレッシュトークンも発行されるパブリッククライアントの場合、これにはリフレッシュトークンのみをDPoPによって公開鍵に紐づける効果があり、保護されたリソースがDPoPをサポートするように修正されていない場合でもセキュリティ機構を改善できます。  

<!---
A client expecting a DPoP-bound access token MAY discard the response, if
a `Bearer` token type is received.
--->
DPoPによって公開鍵に紐づけられたアクセストークンを期待しているクライアントは、 `Bearer` トークンタイプを受信した場合、応答を破棄することが可能です。(**MAY**)

<!---
Refresh tokens issued to confidential clients (those having
established authentication credentials with the authorization server) 
are not bound to the DPoP proof public key because they are already 
sender-constrained with a different existing mechanism. The OAuth 2.0 Authorization 
Framework [RFC6749] already requires that an authorization server bind 
refresh tokens to the client to which they were issued and that 
confidential clients authenticate to the authorization server when 
presenting a refresh token.  As a result, such refresh tokens
are sender-constrained by way of the client ID and the associated 
authentication requirement. This existing sender-constraining mechanism
is more flexible (e.g., it allows credential rotation for the client
without invalidating refresh tokens) than binding directly to a particular public key.
--->
コンフィデンシャルクライアント (認可サーバーでクライアント認証が可能なクライアント)に発行されたリフレッシュトークンは、別の既存のメカニズムで送信者制限が行われているため、DPoP証明によって公開鍵に紐づけません。  
OAuth 2.0 認可フレームワーク[RFC6749]ではもともと、コンフィデンシャルクライアントに対してリフレッシュトークンを発行する際には、認可サーバーが発行先のクライアントに紐づけ、コンフィデンシャルクライアントがリフレッシュトークンを提示するときには認可サーバーに対してクライアント認証をする必要があります。  
その結果、このようなリフレッシュトークンは、クライアントIDおよび関連する認証要件によって送信者に限定されます。  
この既存の送信者限定メカニズムは、特定の公開鍵に直接紐づけるよりも柔軟性があります (たとえば、リフレッシュトークンを無効にすることなく、クライアントの資格情報のローテーションを可能にします) 。  

<!---
## Authorization Server Metadata {#as-meta}
--->
## 認可サーバのメタデータ {#as-meta}

<!---
This document introduces the following new authorization server metadata
[@RFC8414] parameter to signal support for DPoP in general and the specific 
JWS `alg` values the authorization server supports for DPoP proof JWTs.
--->
このドキュメントでは、以下の新しい認可サーバーメタデータ [@RFC8414] パラメーターを定義して、認可サーバーがDPoP証明用のJWTでサポートする、一般的かつ個別の `alg` 値をクライアントに通知できる様にします。

<!---
`dpop_signing_alg_values_supported`
:   A JSON array containing a list of the JWS `alg` values supported
by the authorization server for DPoP proof JWTs. 
--->
`dpop_signing_alg_values_supported`
:   認可サーバーでサポートされているDPoP証明用のJWTに付属するJWSの`alg`値のリストを含むJSON配列。  

<!---
# Public Key Confirmation {#Confirmation}
--->
# 公開鍵の検証 {#Confirmation}

<!---
Resource servers MUST be able to reliably identify whether
an access token is bound using DPoP and ascertain sufficient information
about the public key to which the token is bound in order to verify the
binding with respect to the presented DPoP proof (see (#http-auth-scheme)). 
Such a binding is accomplished by associating the public key 
with the token in a way that can be
accessed by the protected resource, such as embedding the JWK
hash in the issued access token directly, using the syntax described
in (#jwk-thumb-jwt), or through token introspection as described in
(#jwk-thumb-intro). Other methods of associating a
public key with an access token are possible, per agreement by the
authorization server and the protected resource, but are beyond the
scope of this specification.
--->
リソースサーバーは、アクセストークンがDPoPを使用して紐づけられているかどうかを確実に識別し、提示されたDPoP証明に関しての紐付きを検証するために、トークンが紐づけられている公開鍵に関して十分に情報を確かめなければなりません。(**MUST**)  
この紐付き状況の検証は、 (#jwk-thumb-jwt)で説明されている構文を使用して、発行されたアクセストークンにJWKハッシュを直接埋め込むなど、保護されたリソースがアクセスできる方法で公開鍵をトークンに関連付けることによって実現するか、または(#jwk-thumb-intro) で説明されているトークンイントロスペクションを介して実現できます。  
他の方法で、認可サーバーと保護されたリソースサーバーによる合意に従って公開鍵をアクセストークンに関連付けることも可能ですが、この仕様の範囲を超えています。  

<!---
Resource servers supporting DPoP MUST ensure that the public key from
the DPoP proof matches the public key to which the access token is bound.
--->
DPoPをサポートするリソースサーバーは、DPoP証明から取得した公開鍵がアクセストークンが紐づけられている公開鍵と一致することを確認する必要があります。(**MUST**)

<!---
## JWK Thumbprint Confirmation Method {#jwk-thumb-jwt}
--->
## JWTに内包することよる公開鍵の検証方法 {#jwk-thumb-jwt}

<!---
When access tokens are represented as JSON Web Tokens (JWT) [@!RFC7519],
the public key information SHOULD be represented
using the `jkt` confirmation method member defined herein. 
To convey the hash of a public key in a JWT, this specification
introduces the following new JWT Confirmation Method [@!RFC7800] member for
use under the `cnf` claim.
--->
アクセストークンがJSON Web Token(JWT)[@!RFC7519]形式である場合、公開鍵情報は、ここで定義されている `jkt` クレームを使用して表現される必要があります。(**SHOULD**)  
JWTで公開鍵のハッシュを伝達するために、この仕様では新しいJWT確認方法として、`cnf`クレーム[@!RFC7800]のメンバーとして導入しています。  

<!---
`jkt`
:   JWK SHA-256 Thumbprint Confirmation Method. The value of the `jkt` member 
MUST be the base64url encoding (as defined in [@!RFC7515]) 
of the JWK SHA-256 Thumbprint (according to [@!RFC7638]) of the DPoP public key 
(in JWK format) to which the access token is bound. 
--->
`jkt`
:   JWKのためのSHA-256による確認方法。 `jkt`メンバーの値は、アクセストークンが紐づけられているDPoP公開鍵 (JWK形式) のSHA-256ハッシュ ([@!RFC7638]で定義された形式) のbase64urlエンコーディング ([@!RFC7515]で定義された形式) である必要があります。  

<!---
The following example JWT in (#cnf-claim-jwt) with decoded JWT payload shown in 
(#cnf-claim) contains a `cnf` claim with the `jkt` JWK thumbprint confirmation 
method member.  The `jkt` value in these examples is the hash of the public key 
from the DPoP proofs in the examples in (#access-token-request).
--->
次の例は `jkt` クレームとして JWK ハッシュを持つ ` cnf`クレームが含まれているJWTです。
((#cnf-claim) をデコードすると (#cnf-claim-jwt)をペイロードとして含んでいます。)

!---
```
eyJhbGciOiJFUzI1NiIsImtpZCI6IkJlQUxrYiJ9.eyJzdWIiOiJzb21lb25lQGV4YW1
wbGUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJuYmYiOjE
1NjIyNjI2MTEsImV4cCI6MTU2MjI2NjIxNiwiY25mIjp7ImprdCI6IjBaY09DT1JaTll
5LURXcHFxMzBqWnlKR0hUTjBkMkhnbEJWM3VpZ3VBNEkifX0.3Tyo8VTcn6u_PboUmAO
YUY1kfAavomW_YwYMkmRNizLJoQzWy2fCo79Zi5yObpIzjWb5xW4OGld7ESZrh0fsrA
```
!---
<!---
Figure: JWT containing a JWK SHA-256 Thumbprint Confirmation {#cnf-claim-jwt}
--->
Figure: JWK ハッシュを内包するJWT(エンコード済み) {#cnf-claim-jwt}

!---
```
{
  "sub":"someone@example.com",
  "iss":"https://server.example.com",
  "nbf":1562262611,
  "exp":1562266216,
  "cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
}
```
!---
<!---
Figure: JWT Claims Set with a JWK SHA-256 Thumbprint Confirmation {#cnf-claim}
--->
Figure: JWK ハッシュを内包するJWT(デコードしてペイロード部分を抜き出した物) {#cnf-claim}

<!---
## JWK Thumbprint Confirmation Method in Token Introspection {#jwk-thumb-intro}
--->
## トークンイントロスペクションによる公開鍵の検証方法 {#jwk-thumb-intro}

<!---
OAuth 2.0 Token Introspection [@RFC7662] defines a method for a
protected resource to query an authorization server about the active
state of an access token as well as to determine metainformation
about the token.
--->
OAuth 2.0 Token Introspection [@RFC7662]は、保護されたリソースがアクセストークンのアクティブ状態について認可サーバーにクエリを送付し、トークンに関するメタ情報を取得するための方法を定義しています。

<!---
For a DPoP-bound access token, the hash of the public key to which the token 
is bound is conveyed to the protected resource as metainformation in a token
introspection response. The hash is conveyed using the same `cnf` content with 
`jkt` member structure as the JWK thumbprint confirmation method, described in 
(#jwk-thumb-jwt), as a top-level member of the
introspection response JSON. Note that the resource server
does not send a DPoP proof with the introspection request and the authorization 
server does not validate an access token's DPoP binding at the introspection 
endpoint. Rather the resource server uses the data of the introspection response
to validate the access token binding itself locally.
--->
DPoPによって公開鍵に紐づけられたアクセストークンの場合、トークンが紐づけられた公開鍵のハッシュ値は、トークンイントロスペクションレスポンスのメタ情報として保護されたリソースサーバに伝達できます。  
ハッシュ値は、イントロスペクションレスポンスのJSONのトップレベルメンバーとして、(#jwk-thumb-jwt) で説明されているJWKハッシュと同じ形式で、` cnf` クレーム内の `jkt` クレームとして伝達されます。  
リソースサーバーはイントロスペクション要求ではDPoP証明を送信せず、認可サーバーはイントロスペクションエンドポイントでアクセストークンのDPoPを用いた公開鍵の紐づけを検証しないことに注意してください。  
むしろ、リソースサーバーはイントロスペクションレスポンスのデータを使用して、アクセストークンの紐づけ状況をローカルで検証する必要があります。  

<!---
The example introspection request in (#introspect-req) and corresponding response in 
(#introspect-resp) illustrate an introspection exchange for the example DPoP-bound 
access token that was issued in (#token-response).
--->
(#introspect-req) のイントロスペクションリクエストの例と(#introspect-resp)のイントロスペクションレスポンスの例は、(#token-response) の例で発行されたアクセストークン(DPoPで交換鍵と紐付けされた)に対するイントロスペクションによる情報取得を示しています。  

!---
```
POST /as/introspect.oauth2 HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic cnM6cnM6TWt1LTZnX2xDektJZHo0ZnNON2tZY3lhK1Rp

token=Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU
```
!---
<!---
Figure: Example Introspection Request {#introspect-req}
--->
Figure: DPoPで公開鍵と紐づけられたアクセストークンに対するイントロスペクションリクエストの例 {#introspect-req}

!---
```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "active": true,
  "sub": "someone@example.com",
  "iss": "https://server.example.com",
  "nbf": 1562262611,
  "exp": 1562266216,
  "cnf": {"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
}
```
!---
<!---
Figure: Example Introspection Response for a DPoP-Bound Access Token {#introspect-resp}
--->
Figure: DPoPで公開鍵と紐づけられたアクセストークンに対するイントロスペクションレスポンスの例  {#introspect-resp}

<!---
# Protected Resource Access {#protected-resource-access}
--->
# 保護されたリソースへのアクセス {#protected-resource-access}

<!---
To make use of an access token that is bound to a public key
using DPoP, a client MUST prove possession of the corresponding
private key by providing a DPoP proof in the `DPoP` request header.
As such, protected resource requests with a DPoP-bound access token 
necessarily must include both a DPoP proof as per (#the-proof) and 
the access token as described in (#http-auth-scheme).
The DPoP proof MUST include the `ath` claim with a valid hash of the
associated access token.
--->
DPoPを用いて公開鍵に紐づけられたアクセストークンを利用するには、クライアントは、リクエストの `DPoP` ヘッダーにDPoP証明を添付することにより、対応する秘密鍵の所有を証明する必要があります。(**MUST**)  
そのため必然的に、DPoPによって公開鍵に紐づけられたアクセストークンを使用する、保護されたリソースへのリクエストには、 (#the-proof) によるDPoP証明と、 (#http-auth-scheme) で説明されているアクセストークンの両方が含まれている必要があります。(**MUST**)  
DPoP証明には、紐づけられたアクセストークンの有効なハッシュを含む `ath`クレームを含める必要があります。(**MUST**)  

<!---
## The DPoP Authorization Request Header Scheme {#http-auth-scheme}
--->
## DPoP 認可リクエストヘッダーの構造 {#http-auth-scheme}

<!---
A DPoP-bound access token is sent using the `Authorization` request
header field per Section 2 of [@!RFC7235] using an
authentication scheme of `DPoP`. The syntax of the `Authorization` 
header field for the `DPoP` scheme
uses the `token68` syntax defined in Section 2.1 of [@!RFC7235] 
(repeated below for ease of reference) for credentials. 
The Augmented Backus-Naur Form (ABNF) notation [@!RFC5234] syntax 
for DPoP Authorization scheme credentials is as follows:
--->
DPoPによって公開鍵に紐づけられたアクセストークンは、[@!RFC7235]のセクション2にある`Authorization` リクエストヘッダーフィールドを使用して、`DPoP` 認可スキームを使用して送信されます。  
`DPoP` 認可スキームの` Authorization` ヘッダーフィールドの構文は、[@!RFC7235]のセクション2.1で定義されている `token68` 構文を使用します (参照しやすいように以下で繰り返します) 。  
DPoP認証スキームのクレデンシャルの拡張バッカスナウア記法 (ABNF) [@!RFC5234]で表すと構文は次のとおりです。:

!---
```
 token68    = 1*( ALPHA / DIGIT /
                   "-" / "." / "_" / "~" / "+" / "/" ) *"="

 credentials = "DPoP" 1*SP token68
```
!---
<!---
Figure: DPoP Authorization Scheme ABNF
--->
Figure: DPoP認可スキームのABNF

<!---
For such an access token, a resource server MUST check that a DPoP proof
was also received in the `DPoP` header field of the HTTP request, 
check the DPoP proof according to the rules in (#checking), 
and check that the public key of the DPoP proof matches the public
key to which the access token is bound per (#Confirmation). 
--->
このようなアクセストークンの場合、リソースサーバーは、HTTPリクエストの `DPoP`ヘッダーフィールドでもDPoP証明が受信されたことを確認し、(#checking) のルールに従ってDPoP証明を確認し、(#Confirmation) に従ってDPoP証明の公開鍵がアクセストークンが紐づけられている公開鍵と一致することを確認する必要があります。(**MUST**)  

<!---
The resource server MUST NOT grant access to the resource unless all
checks are successful.
--->
すべてのチェックが成功しない限り、リソースサーバーはリソースへのアクセスを許可してはなりません。(**MUST NOT**)

<!---
(#protected-resource-request) shows an example request to a protected
resource with a DPoP-bound access token in the `Authorization` header 
and the DPoP proof in the `DPoP` header.
Following that is (#dpop-proof-pr), which shows the decoded content of that DPoP
proof. The JSON of the JOSE header and payload are shown
but the signature part is omitted. As usual, line breaks and extra whitespace
are included for formatting and readability in both examples.
--->
(#protected-resource-request) は、`Authorization` ヘッダーにDPoPによって公開鍵に紐づけられたアクセストークンを指定し、`DPoP` ヘッダーにDPoP証明を指定して、保護されたリソースへのリクエストを送信する例を示しています。  
続く (#dpop-proof-pr) では、そのDPoP証明のデコードされた内容を示しています。  
ただし、JOSEヘッダーとペイロードのJSONは掲載されていますが、署名部分は省略されています。  
いつものように、両方の例で分かりやすさために改行と余分な空白が含まれています。  

!---
~~~
GET /protectedresource HTTP/1.1
Host: resource.example.org
Authorization: DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj
 oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z
 WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF
 c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E
 OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA
~~~
!---
<!---
Figure: DPoP Protected Resource Request {#protected-resource-request}
--->
Figure: DPoPを用いた保護されたリソースへのリクエスト {#protected-resource-request}

!---
```
{
  "typ":"dpop+jwt",
  "alg":"ES256",
  "jwk": {
    "kty":"EC",
    "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv":"P-256"
  }
}
.
{
  "jti":"e1j3V_bKic8-LAEB",
  "htm":"GET",
  "htu":"https://resource.example.org/protectedresource",
  "iat":1562262618,
  "ath":"fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
}
```
!---
<!---
Figure: Decoded Content of the `DPoP` proof JWT in (#protected-resource-request) {#dpop-proof-pr}
--->
Figure: (#protected-resource-request) 内の`DPoP`証明用JWTをデコードした物 {#dpop-proof-pr}

<!---
Upon receipt of a request for a URI of a protected resource within 
the protection space requiring DPoP authorization, if the request does
not include valid credentials or does not contain an access 
token sufficient for access to the protected resource, the server
can reply with a challenge using the 401 (Unauthorized) status code
([@!RFC7235], Section 3.1) and the `WWW-Authenticate` header field
([@!RFC7235], Section 4.1). The server MAY include the 
`WWW-Authenticate` header in response to other conditions as well.
--->
DPoPによる認可を必要とする保護されたリソースへのURIのリクエストを受信したとき、リクエストに有効な資格情報が含まれていないか、保護されたリソースへのアクセスに十分なアクセストークンが含まれていない場合、サーバーは 401 (Unauthorized) ステータスコード ([@!RFC7235]、セクション3.1) と `WWW-Authenticate`ヘッダーフィールド ([@!RFC7235]、セクション4.1) を使用してチャレンジを応答できます。  
サーバーは、他の条件に応じて「WWW-Authenticate」ヘッダーを含めることができます。(**MAY**)  

<!---
In such challenges:
--->
チャレンジはこの様にします:

<!---
*  The scheme name is `DPoP`.
*  The authentication parameter `realm` MAY be included to indicate the 
scope of protection in the manner described in [@!RFC7235], Section 2.2.
*  A `scope` authentication parameter MAY be included as defined in 
[@!RFC6750], Section 3.
*  An `error` parameter ([@!RFC6750], Section 3) SHOULD be included
to indicate the reason why the request was declined,
if the request included an access token but failed authorization. 
Parameter values are described in Section 3.1 of [@!RFC6750]. 
* An `error_description` parameter ([@!RFC6750], Section 3) MAY be included 
along with the `error` parameter to provide developers a human-readable
explanation that is not meant to be displayed to end-users.
* An `algs` parameter SHOULD be included to signal to the client the 
JWS algorithms that are acceptable for the DPoP proof JWT. 
The value of the parameter is a space-delimited list of JWS `alg` (Algorithm)
 header values ([@!RFC7515], Section 4.1.1).
* Additional authentication parameters MAY be used and unknown parameters 
MUST be ignored by recipients
--->
*  スキームには `DPoP` を使用します。
*  認証パラメータ `realm`は、[@!RFC7235]のセクション2.2で説明されている方法に従って、保護の範囲を示すために含めることができます。(**MAY**)  
*  [@!RFC6750]のセクション3で定義されているように、 `scope` 認証パラメータを含めることができます。(**MAY**)  
*  リクエストにアクセストークンが含まれているが認可に失敗した場合、リクエストが拒否された理由を示すために、 `error` パラメータ ([@!RFC6750]、セクション3) を含める必要があります。(**SHOULD**)  
パラメータの値は、[@!RFC6750]のセクション3.1で説明されています。  
* `error_description` パラメータ ([@!RFC6750]、セクション3) は、開発者にエラーに関する説明を提供するために、`error` パラメータと一緒に含めることができます。(**MAY**)  
このパラメータはエンドユーザーに表示されることを意図していません。  
* DPoP証明用のJWTに受け入れられるJWSアルゴリズムをクライアントに通知するために、`algs` パラメーターを含める必要があります。(**SHOULD**)  
パラメータの値は、スペースで区切られたJWSの`alg` (アルゴリズム) ヘッダー値のリスト ([@!RFC7515]、セクション4.1.1) です。  
* 追加の認証パラメータを使用でき、(**MAY**)  
不明なパラメータは受信者が無視する必要があります。(**MUST**)  

<!---
For example, in response to a protected resource request without
authentication:
--->
保護されたリソースへの認証情報が不足しているリクエストに対するレスポンス例:

!---
```
 HTTP/1.1 401 Unauthorized
 WWW-Authenticate: DPoP realm="WallyWorld", algs="ES256 PS256"
```
!---
<!---
Figure: HTTP 401 Response To A Protected Resource Request Without Authentication 
--->
Figure: 保護されたリソースへのリクエストに認証情報が不足している場合の HTTP 401 レスポンス

<!---
And in response to a protected resource request that was rejected 
because the confirmation of the DPoP binding in the access token failed: 
--->
アクセストークンのDPoPの検証に失敗したために拒否された、保護されたリソース要求への応答例:

!---
```
 HTTP/1.1 401 Unauthorized
 WWW-Authenticate: DPoP realm="WallyWorld", error="invalid_token",
   error_description="Invalid DPoP key binding", algs="ES256"
```
!---
<!---
Figure: HTTP 401 Response To A Protected Resource Request With An Invalid Token 
--->
Figure: 保護されたリソースへのリクエストのDPoP検証に失敗した場合の HTTP 401 レスポンス

<!---
## The Bearer Authorization Request Header Scheme
--->
## ベアラー認可リクエストヘッダーの構成 {#Bearer_Header}

<!---
Protected resources simultaneously supporting both the `DPoP` and `Bearer` 
schemes need to update how evaluation of bearer tokens is performed to prevent 
downgraded usage of a DPoP-bound access tokens. 
Specifically, such a protected resource MUST reject an access
token received as a bearer token per [!@RFC6750], if that token is 
determined to be DPoP-bound. 
--->
`DPoP` スキームと`Bearer` スキームの両方を同時にサポートする保護されたリソースは、DPoPによって公開鍵に紐づけられたアクセストークンの単独での使用を防ぐために、ベアラートークンの評価方法を変更する必要があります。  
具体的には、そのような保護されたリソースは、トークンがDPoPによって公開鍵に紐づけられていると判断された場合、[@!RFC6750] に従ってベアラートークンとして受信したアクセストークンを拒否する必要があります。(**MUST**)  

<!---
A protected resource that supports only [@RFC6750] and is unaware of DPoP 
would most presumably accept a DPoP-bound access token as a bearer token
(JWT [@RFC7519] says to ignore unrecognized claims, Introspection [@RFC7662] 
says that other parameters might be present while placing no functional 
requirements on their presence, and [@RFC6750] is effectively silent on
the content of the access token as it relates to validity).  As such, a 
client MAY send a DPoP-bound access token using the `Bearer` scheme upon 
receipt of a `WWW-Authenticate: Bearer` challenge from a protected resource
(or if it has prior such knowledge about the capabilities of the protected
resource). The effect of this likely simplifies the logistics of phased 
upgrades to protected resources in their support DPoP or even 
prolonged deployments of protected resources with mixed token type support. 
--->
[@RFC6750] のみをサポートし、DPoPを認識しない保護されたリソースは、おそらくDPoPによって公開鍵に紐づけられたアクセストークンをベアラートークンとして受け入れます。  
(JWT [@RFC7519] では認識されないクレームを無視するように説明されており、イントロスペクション [@RFC7662] では他のパラメーターが存在する可能性があると述べていますが、それらの存在に決められた挙動は定義されていません。[@RFC6750] では、有効性に関するアクセストークンの内容について事実上何も説明していません。)  
そのため、クライアントは、保護されたリソースから `WWW-Authenticate：Bearer` チャレンジを受信すると(または、保護されたリソースの認可方法に関する事前知識がある場合に) 、`Bearer` スキームを使用してDPoPによって公開鍵に紐づけられたアクセストークンを送信できます。(**MAY**)  
これらの挙動により、保護されたリソースの段階的なDPoP対応方法や、保護されたリソース上でこれら二つのトークンタイプの長期的な併用が容易になる可能性があります。  

<!---s
# Security Considerations {#Security}
--->
# セキュリティに関する考慮事項 {#Security}

<!---
In DPoP, the prevention of token replay at a different endpoint (see
(#objective)) is achieved through the
binding of the DPoP proof to a certain URI and HTTP method. DPoP, however,
has a somewhat different nature of protection than TLS-based
methods such as OAuth Mutual TLS [@RFC8705] or OAuth Token
Binding [@I-D.ietf-oauth-token-binding] (see also (#Token_Replay) and (#request_integrity)). 
TLS-based mechanisms can leverage a tight integration
between the TLS layer and the application layer to achieve a very high
level of message integrity with respect to the transport layer to which the token is bound
and replay protection in general. 
--->
DPoPでは、別のエンドポイントでのトークンの再生の防止 ( (#objective) を参照) は、DPoP証明を特定のURIおよびHTTPメソッドに紐づけることで実現されています。  
ただし、DPoPは、OAuth Mutual TLS [@RFC8705]や OAuth Token Binding [@I-D.ietf-oauth-token-binding] などのTLSベースの方法とは多少異なる保護の性質を持っています ( (#Token_Replay) および (#request_integrity) を参照)。  
TLSベースのメカニズムでは、トークンが紐づけられているトランスポート層であるTLSとアプリケーション層の間の緊密な統合を活用して、一般的なリプレイ攻撃対策の観点で非常に高いレベルのメッセージ整合性を実現できています。  

<!---
## DPoP Proof Replay {#Token_Replay}
--->
## DPoP証明でのリプレイ攻撃対策 {#Token_Replay}

<!---
If an adversary is able to get hold of a DPoP proof JWT, the adversary
could replay that token at the same endpoint (the HTTP endpoint
and method are enforced via the respective claims in the JWTs). To
prevent this, servers MUST only accept DPoP proofs for a limited time
window after their `iat` time, preferably only for a relatively brief period
(on the order of a few seconds).
Servers SHOULD store, in the context of the request URI, the `jti` value of 
each DPoP proof for the time window in which the respective DPoP proof JWT
would be accepted and decline HTTP requests to the same URI
for which the `jti` value has been seen before. In order to guard against 
memory exhaustion attacks a server SHOULD reject DPoP proof JWTs with unnecessarily
large `jti` values or store only a hash thereof.    
--->
攻撃者がDPoP証明用のJWTを取得できる場合、攻撃者は同じエンドポイントに対してそのトークンを用いたリプレイ攻撃を行えます (HTTPエンドポイントとメソッドはJWTのそれぞれのクレームで制限されています) 。  
このような攻撃を防ぐために、サーバーは`iat` クレームを起点に、限られた時間枠 (できるだけ短い期間、数秒程度) だけDPoP証明を受け入れる様にしなければなりません。 (**MUST**)   
サーバーは、リクエストURIのごとに個々のDPoP証明用のJWTの`jti`の値を保存しておき、その時受信したDPoP証明用のJWTの`jti`値が、タイムウインドウを考慮した上でも以前に使用された値を下回っている場合は拒否をする必要があります。(**SHOULD**)  
メモリ枯渇攻撃を防ぐために、サーバーは、不必要に大きな「jti」値を持つDPoP証明用のJWTを拒否するか、そのハッシュのみを格納する必要があります。(**SHOULD**)  

<!---
Note: To accommodate for clock offsets, the server MAY accept DPoP
proofs that carry an `iat` time in the reasonably near future (e.g., a few
seconds in the future).
--->
Note: 内部時計のずれに対応するために、サーバーは多少未来時間 (たとえば、数秒先) の `iat` を含むDPoP証明を受け入れる場合があります。(**MAY**)  

<!---
## Untrusted Code in the Client Context
--->
## クライアント側で信頼できないコード {#arbitrary-code-execution}

<!---
If an adversary is able to run code in the client's execution context,
the security of DPoP is no longer guaranteed. Common issues in web
applications leading to the execution of untrusted code are cross-site
scripting and remote code inclusion attacks.
--->
攻撃者がクライアント上でコードを実行できる場合、DPoPのセキュリティは保証されなくなります。  
信頼できないコードの実行につながるWebアプリケーションの一般的な問題は、クロスサイトスクリプティングとリモートコードインクルージョン攻撃です。  

<!---
If the private key used for DPoP is stored in such a way that it
cannot be exported, e.g., in a hardware or software security module,
the adversary cannot exfiltrate the key and use it to create arbitrary
DPoP proofs. The adversary can, however, create new DPoP proofs as
long as the client is online, and use these proofs (together with the
respective tokens) either on the victim's device or on a device under
the attacker's control to send arbitrary requests that will be
accepted by servers.
--->
DPoPに使用される秘密鍵が、エクスポートできない方法で保存されている場合 (ハードウェアまたはソフトウェアのセキュリティモジュールなどに保存されている場合) 、攻撃者は鍵を盗み出して使用し、任意のDPoP証明を作成することはできません。  
ただし、攻撃者はクライアントがオンラインである限り、被害者のデバイスで新しいDPoP証明を作成し、被害者のデバイスや攻撃者の制御下にあるデバイスを用いてトークンとともに使用することでサーバが受け入れ得る任意のリクエストを送信できます。  

<!---
To send requests even when the client is offline, an adversary can try
to pre-compute DPoP proofs using timestamps in the future and
exfiltrate these together with the access or refresh token.
--->
クライアントがオフラインの場合でも、攻撃者は未来のタイムスタンプを使用してDPoP証明を事前に生成し、アクセストークンまたはリフレッシュトークンとともにこれらを盗み出し、不正なリクエストを送信する際に悪用することができます。  

<!---
An adversary might further try to associate tokens issued from the
token endpoint with a key pair under the adversary's control. One way
to achieve this is to modify existing code, e.g., by replacing
cryptographic APIs. Another way is to launch a new authorization grant
between the client and the authorization server in an iframe. This
grant needs to be "silent", i.e., not require interaction with the
user. With code running in the client's origin, the adversary has
access to the resulting authorization code and can use it to associate
their own DPoP keys with the tokens returned from the token endpoint.
The adversary is then able to use the resulting tokens on their own
device even if the client is offline.
--->
攻撃者はさらに、トークンエンドポイントから発行されたトークンを、攻撃者の制御下にあるキーペアに紐づけようとする場合があります。  
この攻撃を実現する1つの方法は、暗号化APIを置き換えるなどして、既存の認可コードを変更することです。  
もう1つの方法は、iframeタグを使用して、クライアントと認可サーバーの間で新しい認可フローを開始することです。  
この場合の認可フローは「サイレント」である必要があります。つまり、ユーザーとの対話を必要としない場合に限ります。  
被害者のクライアントのオリジンで実行されているコードを使用すると、攻撃者は結果の認可コードにアクセスでき、それを使用して攻撃者のDPoPキーペアをトークンエンドポイントから返された被害者のトークンに紐づけることができます。  
攻撃者は、クライアントがオフラインの場合でも、入手した被害者のトークンを攻撃者のデバイスで使用できます。  

<!---
Therefore, protecting clients against the execution of untrusted code
is extremely important even if DPoP is used. Besides secure coding
practices, Content Security Policy [@W3C.CSP] can be used as a second
layer of defense against cross-site scripting.
--->
したがって、DPoPが使用されている場合でも、信頼できないコードの実行からクライアントを保護することは非常に重要です。  
安全なコーディング慣行に加えて、コンテンツセキュリティポリシー [@W3C.CSP] は、クロスサイトスクリプティングに対する防御の第2層として使用できます。  

<!---
## Signed JWT Swapping
--->
## 署名されたJWTの交換攻撃 {#signed-jwt-swapping}

<!---
Servers accepting signed DPoP proof JWTs MUST check the `typ` field in the
headers of the JWTs to ensure that adversaries cannot use JWTs created
for other purposes.
--->
署名されたDPoP証明用のJWTを受け入れるサーバーは、JWTのヘッダーの `typ` フィールドをチェックして、他の目的で作成されたJWTを攻撃者が使用できないことを確実にする必要があります。(**MUST**)

<!---
## Signature Algorithms
--->
## 署名アルゴリズム {#signature-algorithms}

<!---
Implementers MUST ensure that only asymmetric digital signature algorithms that
are deemed secure can be used for signing DPoP proofs. In particular,
the algorithm `none` MUST NOT be allowed.
--->
実装者は、安全であると見なされる非対称デジタル署名アルゴリズムのみがDPoP証明の署名に使用できることを確認する必要があります。(**MUST**)  
特に、アルゴリズム「none」は絶対に許可されてはなりません。(**MUST NOT**)  

<!---
## Message Integrity {#request_integrity}
--->
## メッセージの整合性 {#request_integrity}

<!---
DPoP does not ensure the integrity of the payload or headers of
requests. The DPoP proof only contains claims for the HTTP URI and
method, but not, for example, the message body or general request
headers.
--->
DPoPは、リクエストのペイロードまたはヘッダーの整合性を保証しません。  
DPoP証明には、HTTP URIとメソッドのクレームのみが含まれており、たとえば、メッセージのbody部や一般的なリクエストヘッダーは含まれません。  

<!---
This is an intentional design decision intended to keep DPoP simple to use, but
as described, makes DPoP potentially susceptible to replay attacks
where an attacker is able to modify message contents and headers. In
many setups, the message integrity and confidentiality provided by TLS
is sufficient to provide a good level of protection.
--->
これは、DPoPを使いやすくするための意図的な設計ですが、後述の通り、潜在的にリプレイ攻撃の際に攻撃者によるメッセージのbody部とヘッダーの変更を可能にしています。  
多くの設定では、TLSによって提供されるメッセージの整合性と機密性は、適切なレベルの保護を提供するのに十分です。  

<!---
Implementers that have stronger requirements on the integrity of
messages are encouraged to either use TLS-based mechanisms or signed
requests. TLS-based mechanisms are in particular OAuth Mutual TLS
[@RFC8705] and OAuth Token Binding
[@I-D.ietf-oauth-token-binding].
--->
メッセージの整合性に対してより強い要件がある実装者は、TLSベースのメカニズムまたは署名されたリクエストのいずれかを使用することをお勧めします。  
TLSベースのメカニズムとは、特に OAuth Mutual TLS [@RFC8705] と OAuth Token Binding [@I-D.ietf-oauth-token-binding] を指します。  

<!---
Note: While signatures covering other parts of requests are out of the scope of
this specification, additional information to be signed can be
added into DPoP proofs.
--->
Note: リクエストの他の部分をカバーする署名はこの仕様の範囲外ですが、追加で署名したい情報があればDPoP証明に追加できます。  

<!---
##  Access Token and Public Key Binding
--->
##  アクセストークンと公開鍵の紐づけ {#access-token-binding}

<!---
The binding of the access token to the DPoP public key, which is
specified in (#Confirmation), uses a cryptographic hash of the JWK
representation of the public key. It relies
on the hash function having sufficient second-preimage resistance so
as to make it computationally infeasible to find or create another
key that produces to the same hash output value. The SHA-256
hash function was used because it meets the aforementioned
requirement while being widely available.  If, in the future,
JWK thumbprints need to be computed using hash function(s)
other than SHA-256, it is suggested that an additional related JWT
confirmation method member be defined for that purpose,
registered in the respective IANA registry, and used in place of the
`jkt` confirmation method defined herein.
--->
(#Confirmation) で説明されているDPoP公開鍵へのアクセストークンの紐づけ方法では、JWK形式の公開鍵の暗号化ハッシュが使用されています。  
これは、同じハッシュ出力値を生成する別のキーを探索または作成することを計算量的に不可能にすることを目的に、十分な第2原像攻撃に耐性を持つハッシュ関数を必要としています。  
SHA-256ハッシュ関数は、広く利用可能でありながら前述の要件を満たしているために選択されました。  
将来、SHA-256以外のハッシュ関数を使用してJWKのダイジェストを計算する必要が出てきた場合は、その目的のために追加の関連するJWT確認メソッドメンバーを定義し、それぞれのIANAレジストリに登録した上で、ここで定義されている `jkt` による確認方法の代わりに使用することをお勧めします。  

<!---
Similarly, the binding of the DPoP proof to the access token uses a
hash of that access token as the value of the `ath` claim
in the DPoP proof (see (#DPoP-Proof-Syntax)). This relies on the value
of the hash being sufficiently unique so as to reliably identify the
access token. The collision resistance of SHA-256 meets that requirement.
If, in the future, access token digests need be computed using hash function(s)
other than SHA-256, it is suggested that an additional related JWT
claim be defined for that purpose, registered in the respective IANA registry,
 and used in place of the `ath` claim defined herein.
--->
同様に、DPoP証明のアクセストークンへの紐づけは、そのアクセストークンのハッシュをDPoP証明の `ath` クレームの値として使用します ( (#DPoP-Proof-Syntax) を参照) 。  
これは、アクセストークンを確実に識別するために、ハッシュの値が十分に一意であることに依存しています。  
SHA-256の衝突耐性はその要件を満たしています。  
将来、SHA-256以外のハッシュ関数を使用してアクセストークンのダイジェストを計算する必要が出てきた場合は、その目的のために追加のJWTクレームを定義し、それぞれのIANAレジストリに登録した上で、ここで定義されている「ath」クレームの代わりに使用することをお勧めします。  

Similarly, the binding of the DPoP proof to the access token uses a hash of that access token as the value of the `ath` claim in the DPoP proof (see (#DPoP-Proof-Syntax)).
This relies on the value of the hash being sufficiently unique so as to reliably identify the access token. The collision resistance of SHA-256 meets that requirement.
If, in the future, access token digests need be computed using hash function(s) other than SHA-256, it is suggested that an additional related JWT claim be defined for that purpose, registered in the respective IANA registry,  and used in place of the `ath` claim defined herein.

<!---
# IANA Considerations {#IANA}
--->
# IANAの考慮事項 {#IANA}

<!---
##  OAuth Access Token Type Registration
--->
##  OAuthアクセストークンタイプの登録 {#access-token-type-registration}

<!---
This specification requests registration of the following access token
type in the "OAuth Access Token Types" registry [@IANA.OAuth.Params]
established by [@!RFC6749].
--->
この仕様では、[@!RFC6749] によって定義された OAuthアクセストークンタイプレジストリ [@IANA.OAuth.Params] に次のアクセストークンタイプの登録を要求しています。  

<!---
 * Type name: `DPoP`
 * Additional Token Endpoint Response Parameters: (none)
 * HTTP Authentication Scheme(s): `DPoP`
 * Change controller: IESG
 * Specification document(s): [[ this specification ]]
--->
 * タイプ名: `DPoP`
 * 追加のトークンエンドポイントのレスポンスパラメータ: (なし)
 * HTTP認証スキーム: `DPoP`
 * 仕様の管理者: IESG
 * 仕様書: [[ this specification ]]

<!---
## HTTP Authentication Scheme Registration
--->
## HTTP認証スキームの登録 {#http-authentication-scheme-registration}

<!---
This specification requests registration of the following scheme in the 
"Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry" [@RFC7235;@IANA.HTTP.AuthSchemes]:
--->
この仕様では、[@RFC7235] によって定義された Hypertext Transfer Protocol (HTTP) 認証スキームレジストリ [@IANA.HTTP.AuthSchemes] に次のスキームの登録を要求しています。  

<!---
 * Authentication Scheme Name: `DPoP`
 * Reference: [[ (#http-auth-scheme) of this specification ]]
--->
 * 認証スキーム名: `DPoP`
 * 仕様書: [[ (#http-auth-scheme) of this specification ]]

<!---
## Media Type Registration
--->
## メディアタイプの登録 {#media-type-registration}

<!---
[[
Is a media type registration at [@IANA.MediaTypes] necessary for `application/dpop+jwt`? 
There is a `+jwt` structured syntax suffix registered already at [@IANA.MediaType.StructuredSuffix]
by Section 7.2 of [@RFC8417], which is maybe sufficient? A full-blown registration
of `application/dpop+jwt` seems like it'd be overkill. 
The `dpop+jwt` is used in the JWS/JWT `typ` header for explicit typing of the JWT per 
Section 3.11 of [@RFC8725] but it is not used anywhere else (such as the `Content-Type` of HTTP messages). 

Note that there does seem to be some precedence for [@IANA.MediaTypes] registration with 
 [@I-D.ietf-oauth-access-token-jwt], [@I-D.ietf-oauth-jwsreq], [@RFC8417], and of course [@RFC7519].
But precedence isn't always right. 
]]
--->

以下の通り議論中であり、未確定です。

```
  Is a media type registration at [@IANA.MediaTypes] necessary for `application/dpop+jwt`? 
  There is a `+jwt` structured syntax suffix registered already at [@IANA.MediaType.StructuredSuffix]
  by Section 7.2 of [@RFC8417], which is maybe sufficient? A full-blown registration
  of `application/dpop+jwt` seems like it'd be overkill. 
  The `dpop+jwt` is used in the JWS/JWT `typ` header for explicit typing of the JWT per 
  Section 3.11 of [@RFC8725] but it is not used anywhere else (such as the `Content-Type` of HTTP messages). 

  Note that there does seem to be some precedence for [@IANA.MediaTypes] registration with 
  [@I-D.ietf-oauth-access-token-jwt], [@I-D.ietf-oauth-jwsreq], [@RFC8417], and of course [@RFC7519].
  But precedence isn't always right. 
```

<!---
## JWT Confirmation Methods Registration
--->

## JWT検証方法の登録 {#jwt-confirmation-method-registration}

<!---
This specification requests registration of the following value
in the IANA "JWT Confirmation Methods" registry [@IANA.JWT]
for JWT `cnf` member values established by [@!RFC7800].
--->
この仕様では、[@!RFC7800]によって定義された JWT `cnf` クレームの値について、IANAのJWT検証方法レジストリ [@IANA.JWT] に次の値の登録を要求しています。  

<!---
 * Confirmation Method Value:  `jkt`
 * Confirmation Method Description: JWK SHA-256 Thumbprint
 * Change Controller:  IESG
 * Specification Document(s):  [[ (#Confirmation) of this specification ]]
--->
 * 検証方法の値:  `jkt`
 * 検証方法の説明: JWK SHA-256 Thumbprint
 * 仕様の管理者:  IESG
 * 仕様書:  [[ (#Confirmation) of this specification ]]

<!---
## JSON Web Token Claims Registration
--->
## JWTクレームの登録 {#jwt-claims-registration}

<!---
This specification requests registration of the following Claims in the 
IANA "JSON Web Token Claims" registry [@IANA.JWT] established by [@RFC7519].
--->
この仕様では、[@RFC7519] によって定義された IANA JSON Web Token Claims レジストリ [@IANA.JWT] に次のクレームの登録を要求しています。  

<!---
HTTP method:
--->
HTTPメソッド:

<!---
 *  Claim Name: `htm`
 *  Claim Description: The HTTP method of the request 
 *  Change Controller: IESG
 *  Specification Document(s):  [[ (#DPoP-Proof-Syntax) of this specification ]]
--->
 *  クレーム名: `htm`
 *  クレームの説明: The HTTP method of the request 
 *  仕様の管理者: IESG
 *  仕様書:  [[ (#DPoP-Proof-Syntax) of this specification ]]

<!---
HTTP URI:
--->
HTTP URI:

<!---
 *  Claim Name: `htu`
 *  Claim Description: The HTTP URI of the request (without query and fragment parts)
 *  Change Controller: IESG
 *  Specification Document(s):  [[ (#DPoP-Proof-Syntax) of this specification ]]
--->
 *  クレーム名: `htu`
 *  クレームの説明: The HTTP URI of the request (without query and fragment parts)
 *  仕様の管理者: IESG
 *  仕様書:  [[ (#DPoP-Proof-Syntax) of this specification ]]

<!---
 Access token hash:
--->
アクセストークンハッシュ:

<!---
 *  Claim Name: `ath`
 *  Claim Description: The base64url encoded SHA-256 hash of the ASCII encoding of the associated access token's value
 *  Change Controller: IESG
 *  Specification Document(s):  [[ (#DPoP-Proof-Syntax) of this specification ]]
--->
 *  クレーム名: `ath`
 *  クレームの説明: The base64url encoded SHA-256 hash of the ASCII encoding of the associated access token's value
 *  仕様の管理者: IESG
 *  仕様書:  [[ (#DPoP-Proof-Syntax) of this specification ]]

<!---
## HTTP Message Header Field Names Registration
--->
## HTTPヘッダーの登録 {#http-header-registration}

<!---
This document specifies the following new HTTP header fields,
registration of which is requested in the "Permanent Message Header
Field Names" registry [@IANA.Headers] defined in [@RFC3864].
--->
この仕様では、[@RFC3864] によって定義された Permanent Message Header Field Names レジストリ [@IANA.Headers] に次の新しいHTTPヘッダーフィールドの登録を要求しています。  

<!---
 *  Header Field Name: `DPoP`
 *  Applicable protocol: HTTP
 *  Status: standard
 *  Author/change Controller: IETF
 *  Specification Document(s): [[ this specification ]]
--->
 *  ヘッダー名: `DPoP`
 *  プロトコル: HTTP
 *  ステータス: standard
 *  仕様の管理者: IETF
 *  仕様書: [[ this specification ]]

<!---
## Authorization Server Metadata Registration
--->
## 認可サーバーのメタデータの登録 {#authorization-server-metadata-registration}

<!---
This specification requests registration of the following values
in the IANA "OAuth Authorization Server Metadata" registry [IANA.OAuth.Parameters]
established by [@RFC8414].
--->
この仕様では、[@RFC8414]によって定義された IANA OAuthAuthorization Server Metadata レジストリ [IANA.OAuth.Parameters] にの次の値の登録を要求しています。

<!---
 *  Metadata Name:  `dpop_signing_alg_values_supported`
 *  Metadata Description:  JSON array containing a list of the JWS algorithms supported for DPoP proof JWTs
 *  Change Controller:  IESG
 *  Specification Document(s):  [[ (#as-meta) of this specification ]]
--->
 *  メタデータ名:  `dpop_signing_alg_values_supported`
 *  メタデータの説明:  JSON array containing a list of the JWS algorithms supported for DPoP proof JWTs
 *  仕様の管理者:  IESG
 *  仕様書:  [[ (#as-meta) of this specification ]]

{backmatter}

<!---
# Acknowledgements {#Acknowledgements}
--->
# 謝辞 {#Acknowledgements}

<!---
We would like to thank 
--->
私たちは以下の方々に感謝をしています。  

Annabelle Backman,
Dominick Baier,
Andrii Deinega,
William Denniss,
Vladimir Dzhuvinov,
Mike Engan,
Nikos Fotiou,
Mark Haine,
Dick Hardt,
Bjorn Hjelm,
Jared Jennings,
Steinar Noem,
Neil Madden,
Rob Otto,
Aaron Parecki,
Michael Peck,
Paul Querna,
Justin Richer,
Filip Skokan,
Dave Tonge,
Jim Willeke,
Philippe De Ryck,

<!---
and others (please let us know, if you've been mistakenly omitted)
for their valuable input, feedback and general support of this work.
--->
及びその他の皆様(誤って掲載できていない方に気がついたら、私たちに連絡を下さい)  
この仕様策定に対する貴重な意見、フィードバック、および一般的なサポートに感謝します。  

<!---
This document resulted from discussions at the 4th OAuth Security
Workshop in Stuttgart, Germany. We thank the organizers of this
workshop (Ralf Kusters, Guido Schmitz).
--->
このドキュメントは、ドイツのシュトゥットガルトで開催された第4回OAuthセキュリティワークショップでの議論の成果です。  
このワークショップの主催者 (Ralf Kusters、Guido Schmitz) に感謝します。  

<!---
# Document History
--->
# 修正履歴 {#document-history}

   [[ To be removed from the final specification ]]

  -04
 
  -03

  * Add an access token hash (`ath`) claim to the DPoP proof when used in conjunction with the presentation of an access token for protected resource access
  * add Untrusted Code in the Client Context section to security considerations
  * Editorial updates and fixes

  -02
  
   * Lots of editorial updates and additions including expanding on the objectives, 
     better defining the key confirmation representations, example updates and additions, 
     better describing mixed bearer/dpop token type deployments, clarify RT binding only being
     done for public clients and why, more clearly allow for a bound RT but with bearer AT, 
     explain/justify the choice of SHA-256 for key binding, and more
   * Require that a protected resource supporting bearer and DPoP at the same time
     must reject an access token received as bearer, if that token is DPoP-bound
   * Remove the case-insensitive qualification on the `htm` claim check
   * Relax the jti tracking requirements a bit and qualify it by URI
  
   
  -01
  
   * Editorial updates
   * Attempt to more formally define the DPoP Authorization header scheme
   * Define the 401/WWW-Authenticate challenge 
   * Added `invalid_dpop_proof` error code for DPoP errors in token request 
   * Fixed up and added to the IANA section
   * Added `dpop_signing_alg_values_supported` authorization server metadata
   * Moved the Acknowledgements into an Appendix and added a bunch of names (best effort)
   
   -00 [[ Working Group Draft ]]

   * Working group draft

   -04

   * Update OAuth MTLS reference to RFC 8705
   * Use the newish RFC v3 XML and HTML format

   -03 
   
   * rework the text around uniqueness requirements on the jti claim in the DPoP proof JWT
   * make tokens a bit smaller by using `htm`, `htu`, and `jkt` rather than `http_method`, `http_uri`, and `jkt#S256` respectively
   * more explicit recommendation to use mTLS if that is available
   * added David Waite as co-author
   * editorial updates 

   -02
   
   * added normalization rules for URIs
   * removed distinction between proof and binding
   * "jwk" header again used instead of "cnf" claim in DPoP proof
   * renamed "Bearer-DPoP" token type to "DPoP"
   * removed ability for key rotation
   * added security considerations on request integrity
   * explicit advice on extending DPoP proofs to sign other parts of the HTTP messages
   * only use the jkt#S256 in ATs
   * iat instead of exp in DPoP proof JWTs
   * updated guidance on token_type evaluation


   -01
   
   * fixed inconsistencies
   * moved binding and proof messages to headers instead of parameters
   * extracted and unified definition of DPoP JWTs
   * improved description


   -00 

   *  first draft
   

<reference anchor="IANA.OAuth.Params" target="https://www.iana.org/assignments/oauth-parameters">
 <front>
   <title>OAuth Parameters</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>

<reference anchor="IANA.MediaType.StructuredSuffix" target="https://www.iana.org/assignments/media-type-structured-suffix">
 <front>
   <title>Structured Syntax Suffix Registry</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>

<reference anchor="IANA.MediaTypes" target="https://www.iana.org/assignments/media-types">
 <front>
   <title>Media Types</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>

<reference anchor="IANA.HTTP.AuthSchemes" target="https://www.iana.org/assignments/http-authschemes">
 <front>
   <title>Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>

<reference anchor="IANA.JWT" target="http://www.iana.org/assignments/jwt">
<front>
  <title>JSON Web Token Claims</title>
  <author><organization>IANA</organization></author>
  <date/>
</front>
</reference>

<reference anchor="IANA.Headers" target="https://www.iana.org/assignments/message-headers">
<front>
  <title>Message Headers</title>
  <author><organization>IANA</organization></author>
  <date/>
</front>
</reference>

<reference anchor="W3C.WebCryptoAPI" target="https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126">
<front>
  <title>Web Cryptography API</title>
  <author initials="M." surname="Watson" fullname="Mark Watson"><organization/></author>
  <date month="January" day="26" year="2017"/>
</front>
<seriesInfo name="World Wide Web Consortium Recommendation" value="REC-WebCryptoAPI-20170126"/>
<format type="HTML" target="https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126"/>
</reference>



<reference anchor="W3C.CSP" target="https://www.w3.org/TR/2018/WD-CSP3-20181015/">
<front>
  <title>Content Security Policy Level 3</title>
  <author initials="M." surname="West" fullname="Mike West"><organization/></author>
  <date month="October" day="15" year="2018"/>
</front>
<seriesInfo name="World Wide Web Consortium Working Draft" value="WD-CSP3-20181015"/>
<format type="HTML" target="https://www.w3.org/TR/2018/WD-CSP3-20181015/"/>
</reference>
