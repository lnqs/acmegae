# Let's Encrypt for Google AppEngine

This repository contains tools to create Let's Encrypt certificates for Google
AppEngine projects.

## Setup
### Server-side code
Copy the well\_known subdirectory to your Google AppEngine project.
There's a file called *handler.yaml* inside, that you need to include in your app.yaml.

Deploy your application after you included it!

### Google Service Account
Visit the [Credentials page of the API Manager in Google Cloud Console](https://console.cloud.google.com/apis/credentials) and create a new Service Account. Download the key as JSON.

### Create configuration
Run the create\_key.py-script to create a private key for your Let's Encrypt account and set the configuration
for creating certificates:

```
./generate_certificate/create_key.py --email=your@mail.com --google-credentials=file_just_downloaded_for_service_account.json yourdomain.com www.yourdomain.com > configuration.json
```

*configuration.json* should contain all required information then.
Please keep this file in a safe place. It contains both a private key to access your Google AppEngine project,
as well as the private key you'll register yourself at Let's Encrypt with soon.

## Creating certificates
To create a certificate, you just need to run

```
./generate_certificate/generate_certificate.py configuration.json > certificates.pem
```

The last step has to be done manually.
Visit the [certificate configuration in the Google AppEngine settings](https://console.cloud.google.com/appengine/settings/certificates), create a new certificate and upload the contents of *certificates.pem*.

## Credits
This repository contains some code from the [simp\_le-Project](https://github.com/kuba/simp_le).
