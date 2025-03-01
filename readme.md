# Cybersecuritybase mooc project 1

- https://cybersecuritybase.mooc.fi/module-3.1
- https://web.archive.org/web/20250301081009/https://cybersecuritybase.mooc.fi/module-3.1

## Flaws:

### 1. A03:2021-Injection

- CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)

---

- https://github.com/antoKeinanen/cybersecuritybase-mooc-project-1/blob/main/project/pages/templates/pages/index.html#L39

When user posts a new message the message is not properly sanitized. This makes it possible for attackers to perform a XSS attack where user input is processed as javascript code and executed on the victim's machine. This could be showcased by posting `<script>alert(1)</script>` and observing everyone loading the page getting the popup that says '1'. This could be easily prevented by removing the safe attribute from `{{post.content | safe}}` to `{{post.content}}`.

### 2. Vulnerability 2: A03:2021 - Injection

- CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

---

- https://github.com/antoKeinanen/cybersecuritybase-mooc-project-1/blob/main/project/pages/views.py#L31
- https://github.com/antoKeinanen/cybersecuritybase-mooc-project-1/blob/main/project/pages/views.py#L64

In login and sign up api endpoints user submitted credentials are not sanitized correctly. This allows attackers to execute arbitrary SQL commands on the server. As a slight mitigation the attacker can only modify the end of the query and can not add additional queries. Best way to showcase this flaw is by inputting `<username>' --` to `/signin` page's username field and then checking the cookie. This exploit allows the attacker to obtain the password to any user.

### 3. A02:2021 - Cryptographic failures

- CWE-261 Weak Encoding for Password

---

- https://github.com/antoKeinanen/cybersecuritybase-mooc-project-1/blob/main/project/pages/views.py#L31

The application does not hash passwords when storing them in the database. This in itself is not a bad thing, but when an attacker manages to connect to the database or gets the rows with an sql injection all the passwords will be leaked. This could be mitigated by hashing the passwords with a strong enough hashing algorithm like argon2id. The passwords should also be salted before inserting into the database. Salting prevents the attackers from using rainbow-tables when cracking the password hash. It also prevents attackers from seeing if 2 passwords are the same by comparing the hashes.

### 4. A05:2021 - Security Misconfiguration

- CWE-315 Cleartext Storage of Sensitive Information in a Cookie
- CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag

---

- https://github.com/antoKeinanen/cybersecuritybase-mooc-project-1/blob/main/project/pages/views.py#L47
- https://github.com/antoKeinanen/cybersecuritybase-mooc-project-1/blob/main/project/pages/views.py#L82-L87

This flaw consists of 3 different flaws combined. The first that the password is stored in the cookie in plain text. An attacker could in theory extract the cookie and then compromise the victim's account that way. The second and third flaws are that the cookie is misconfigured. As the cookie is not needed by any client-side scripts it should have the HttpOnly flag set to true. This prevents any attackers from obtaining the cookie with a XSS attack. The secure flag should also be set. This prevents the cookie to be sent in an unsecure context. Unsecure context is defined by the browser and usually means a connection without encryption. The issues could be fixed by using tokens instead of plaintext password and configuring the cookie correctly by setting HttpOnly and Secure flags to true.

### 5. A07:2021 - Identification and Authentication Failures

- CWE-306 Missing Authentication for Critical Function

---

- https://github.com/antoKeinanen/cybersecuritybase-mooc-project-1/blob/main/project/pages/views.py#L116

Users are not properly authenticated when creating a new post. This happens because the server does not validate the password when getting the User object from the database. This could be easily fixed by adding another condition to the user query where the password is also checked.
