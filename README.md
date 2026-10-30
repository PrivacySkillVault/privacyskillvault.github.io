# Privacy Skill Vault

The main Privacy Skill Vault website is built with MkDocs Material and published at https://privacyskillvault.com/.

## Local development

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install mkdocs-material
mkdocs serve
~~~

Build the static site before publishing:

~~~bash
mkdocs build --strict
~~~

## Content standards

- Label professional experience, lab-tested work, simulated scenarios, and research notes accurately.
- Do not publish customer data, internal system details, credentials, or employer-confidential information.
- Test commands and detection logic in an authorised environment before recommending operational use.
- Keep the primary navigation and canonical content on the main domain.
