CaptchEtat
==========

Presentation
------------

Captcha module using the `CaptchEtat <https://api.gouv.fr/les-api/api-captchetat>`__
service provided by the French government through the
`PISTE <https://piste.gouv.fr>`__ platform. Supports image and audio captcha.

Prerequisites:

- An account on `PISTE <https://piste.gouv.fr>`__
- An access request via `DataPass <https://datapass.api.gouv.fr/demandes/api-captchetat/nouveau>`__

Configuration
-------------

Configure captcha like :doc:`LLNG internal captcha<captcha>` but use a
"custom captcha module", set:

- **Captcha module** to "``::Captcha::CaptchEtat``"
- in **Captcha module options**, add the following keys

   - ``clientId``: the PISTE OAuth2 client ID
   - ``clientSecret``: the PISTE OAuth2 client secret
   - ``captchaType`` *(optional)*: captcha style, default ``captchaFR``. See available types below
   - ``sandbox`` *(optional)*: set to ``1`` to use the PISTE sandbox environment

Available captcha types
~~~~~~~~~~~~~~~~~~~~~~~

+------------------------------------------+------------+----------------+
| Value                                    | Characters | Type           |
+==========================================+============+================+
| ``captchaFR`` (default)                  | 6-9        | Alphanumeric   |
+------------------------------------------+------------+----------------+
| ``captchaEN``                            | 6-9        | Alphanumeric   |
+------------------------------------------+------------+----------------+
| ``numerique6_7CaptchaFR``                | 6-7        | Numeric        |
+------------------------------------------+------------+----------------+
| ``alphabetique6_7CaptchaFR``             | 6-7        | Alphabetic     |
+------------------------------------------+------------+----------------+
| ``alphanumerique12CaptchaFR``            | 12         | Alphanumeric   |
+------------------------------------------+------------+----------------+
| ``alphanumerique6to9LightCaptchaFR``     | 6-9        | Alphanumeric   |
+------------------------------------------+------------+----------------+
| ``alphanumerique4to6LightCaptchaFR``     | 4-6        | Alphanumeric   |
+------------------------------------------+------------+----------------+

English variants (``EN``) are available for each type.
