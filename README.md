# Experimental Snyk plugin for Pants Build

## Disclaimer
This plugin is not officially supported by Snyk. It's simply hitting Snyk's public APIs [API Doc](https://snyk.docs.apiary.io/).
Snyk public APIs require a [paid plan]https://snyk.io/plans/. You can start a trial to kick the tires.

## What is does
It currently tests jvm based and python based projects. One time test upon command.

## What is does NOT do (today at least)
It does not monitor projects, does not upload any results in Snyk UI or reporting.

## Installation
1. Drop the snyk folder into your pants build plugins folder.
2. Add to your pants.ini the following lines
```
backend_packages: +[
    'snyk'
]
```

and 

```
pythonpath: +[
    "%(buildroot)s/plugins"
]
```

3. Set the following ENV VARS
`SNYK_TOKEN` with your Snyk token (look under account)
`SNYK_ORG` with your Snyk ORG Id (look under settings)

4. (Optional) Set `SNYK_API` env var to point to your private Snyk instance

## Usage
`./pants snyktest <target>`

use `--snyk-snyktest-json` option to get the raw json response from the API.



  
