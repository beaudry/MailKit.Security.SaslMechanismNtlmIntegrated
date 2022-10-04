# MailKit.Security.SaslMechanismNtlmIntegrated
This is a package that contains the code given by [UriHendler](https://github.com/UriHendler) in the issue [#332](https://github.com/jstedfast/MailKit/issues/332#issuecomment-398300208) of [MailKit](https://github.com/jstedfast/MailKit).

With this mechanism, you achieve a similar result as if you were to use the `UseDefaultCredentials()` of the .Net SmtpClient.

## How to use
```
using MailKit.Security;

smtpClient.Authenticate(new SaslMechanismNtlmIntegrated());
```
