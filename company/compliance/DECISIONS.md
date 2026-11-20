<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Open legal decisions

Decisions that must be made before LUME is released to the public. Each one is
closed by a decision of the director, with a lawyer admitted to practise in the
Republic of Kazakhstan where needed. Once a decision is made, its outcome goes
into the documents in `legal/` and its row is removed from here.

| No. | Question | Why it matters | Recommendation |
|---|---|---|---|
| 1 | **Contract with the data centre** | Settled: the server will be hosted in a data centre in Kazakhstan. The provider processes data on behalf of LUME Inc. (ТОО «LUME Inc.») and must be bound by a contract | A contract with terms on processing personal data on the company's behalf, confidentiality, security measures, access to the equipment and incident notification; then enter the provider's name in `legal/PRIVACY.md` |
| 2 | **Data subject in the consent without a full name** | Paragraph 4 of article 8 of Law No. 94-V lists the subject's full name among the details of a consent; LUME does not collect names | A legal opinion that a subject identified by username and key is enough, or another method "that makes it possible to confirm that consent was obtained" |
| 3 | **Proof of consent** | Sub-paragraph 5) of paragraph 2 of article 25 requires the operator to provide proof of consent; as specified, the relay does not record which version of the consent a user accepted | Add the number of the accepted version to the `Register` request and store it with the day of registration in the `accounts` table (a change to `docs/PROTOCOL.md` §4.2 and §7) |
| 4 | **Russia and RuStore** | Distribution in Russia may lead Roskomnadzor to require registration as an organiser of information distribution (Federal Law No. 149-FZ, article 10.1): storing metadata in Russia, identifying users and giving the FSB the means to decrypt. This cannot be reconciled with end-to-end encryption, and refusal leads to blocking. Federal Law No. 152-FZ also requires the data of Russian citizens to be stored in Russia | Do not publish in RuStore and do not target Russia (prices, domain, advertising) until a separate decision is made with a lawyer |
| 5 | **EU representative** | GDPR article 27 and DSA article 13 require a representative for a service from outside the EU that is offered to users in the EU; a messenger in continuous use does not fall under the exemption for "occasional" processing | Appoint a representative (specialised firms provide this service) before LUME is opened to the EU, or do not offer LUME in the EU until then |
| 6 | **LUME trademark** | Without registration the name is less well protected; the documents still refer to it as a designation | File an application with the NIIP for the word mark LUME in classes 9, 38 and 42 (about KZT 126,000 for a small or medium-sized business), then for the logo; decide on international registration within 6 months. Everything is prepared in [TRADEMARK.md](TRADEMARK.md) |
| 7 | **Contact addresses** | The policies refer to addresses that do not exist yet; the DSA requires single points of contact for authorities and users | Set up separate addresses: personal data, child safety, public authorities, complaints and claims, general |
| 8 | **Website: hosting and logs** | Settled: the website is on GitHub Pages. GitHub records visitors' IP addresses itself, as an independent operator; LUME Inc. receives no logs. The site sets no cookies and uses no local or session storage (`legal/WEBSITE.md`) | A lawyer confirms that with this hosting the requirement to store visitors' IP addresses in Kazakhstan does not apply to the company; if it does, move the site to a server in a data centre in Kazakhstan |
| 9 | **Notifying the authorised body (article 10-1)** | Small and medium-sized operators (up to 500,000 unique data subjects) are exempt | Do not notify for now; track the number of accounts and file the notification before the threshold is reached |
| 10 | **Law "On Online Platforms and Online Advertising"** | It is unclear whether it applies to messengers; it sets requirements for the interface and the user agreement in Kazakh | A lawyer's opinion. The documents are published in English only, so the opinion must also say whether the interface and the user agreement need a Kazakh version |
| 11 | **Language of the documents** | The documents are published in English only. The Kazakh and Russian versions were removed on 6 November 2026 | A lawyer confirms that English alone is enough, or names the documents that need a Kazakh or Russian version |
| 12 | **Legal review of the whole set** | The documents are written as drafts | A review by a lawyer admitted to practise in Kazakhstan before the first public release |
