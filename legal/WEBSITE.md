<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# The LUME website: privacy and cookies

**Status: draft.** Takes effect on the day the website is first published; this
line will then be replaced by that date.
Русская версия: [WEBSITE.ru.md](WEBSITE.ru.md).
Қазақша нұсқа: [WEBSITE.kk.md](WEBSITE.kk.md).

This page covers only the LUME website. The apps and the relay are covered by
the [Privacy Policy](PRIVACY.md).

## 1. In short

- **Two cookies of its own.** The necessary one remembers your choice in the
  cookie window. The other remembers the site's language and is set only if you
  allow it.
- **No analytics, trackers or ads**, no visitor counters and no browser
  fingerprinting.
- **One script**, `site.js`, from this same site. It shows the cookie window,
  saves your choice and lets the home page's headline appear out of a
  "cipher"; it does nothing else and sends nothing anywhere. The site works
  fully without it: the text is there at once, except that the cookie window
  does not appear and no cookie is set. Other animation is done in the
  stylesheet. All of it switches off when your system asks for reduced motion.
- **Nothing from other servers.** Fonts and images are served by this site;
  there are no CDNs, embedded videos, maps or social buttons. A strict Content
  Security Policy makes the browser enforce this.
- **No forms.** The site asks you to type nothing.
- **No referrer.** When you follow a link to another site, your browser is told
  not to reveal which page you came from.

## 2. Cookies

| Cookie | Category | What it holds | Lifetime | When it is set |
|---|---|---|---|---|
| `lume_consent` | Necessary | the version of the cookie window and whether preference cookies are allowed, such as `1.0` | 6 months | when you make a choice in the cookie window |
| `lume_lang` | Preferences | the site's language: `kk`, `ru` or `en` | 12 months | when you open a page, if you allowed preference cookies |

- Both cookies are set by this site itself; there are no third-party cookies.
- They hold no identifier: they cannot tell you apart from any other visitor
  who made the same choice, and cannot tell who you are.
- Your browser sends them only with requests to this site. Only this site's
  pages in your browser use them.
- There are no analytics or advertising cookies. If they are ever needed, we
  will change this page first and the site will ask for your consent again;
  without it they will not be set.

**Grounds.** The necessary cookie carries out your own choice and is set
without separate consent, as article 5(3) of Directive 2002/58/EC allows for
what is strictly necessary for a service the user asks for. The preference
cookie is set only with your consent. Neither cookie holds anything that could
identify a person, but we ask for consent the way the strictest of the rules
that apply require.

## 3. Changing your choice

- The **Cookie settings** link at the bottom of every page opens a window where
  preference cookies can be turned on or off. Withdrawing consent is as easy as
  giving it.
- When you turn preference cookies off, `lume_lang` is deleted at once.
- After 6 months, and whenever the list of cookies changes, the site asks you
  again.
- You can delete this site's cookies in your browser's settings; the site will
  then ask again. If JavaScript is off in your browser, the window does not
  appear and the site sets no cookie at all.

## 4. Hosting and what it receives

The website is hosted on GitHub Pages, a service of GitHub, Inc. (USA). To send
you a page, GitHub's server receives what your browser sends with any request:
your IP address, the address of the page, the time of the request, your
browser's user-agent string and this site's cookies. Under its own rules GitHub
logs the IP addresses of visitors to GitHub Pages sites for security purposes
and processes them on its own account, under the
[GitHub General Privacy Statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).

LUME Inc. receives no access logs and does not see visitors' IP addresses. When
you open the site, your browser connects to GitHub's servers directly; those
servers may be outside the Republic of Kazakhstan.

## 5. Links to other sites

The website links to GitHub, where the source code is, and to the websites of
the libraries LUME uses. Nothing is loaded from those sites until you follow a
link; once you do, their own privacy policies apply.

## 6. Your rights

Your rights are those in section 9 of the [Privacy Policy](PRIVACY.md). LUME
Inc. keeps nothing about visitors to the website: both cookies live only in your
browser, and you control them yourself, through Cookie settings or your
browser's settings. Questions about data GitHub processes go to GitHub. How to
reach us is on the [contact page](CONTACT.md).

## 7. Changes

Changes to this page are made in our public repository, where its whole history
can be seen. When the list of cookies changes, the site asks for consent again.
