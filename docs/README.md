# Documentation

Three documents, each answering one question. If something here disagrees with
the code, the code is right and the document is a bug — say so.

| | Answers |
|---|---|
| [`PROTOCOL.md`](PROTOCOL.md) | **What the API does.** Endpoints, the WebSocket protocol, the encrypted payload format, error shapes, and the table of rate limits. |
| [`DDOS.md`](DDOS.md) | **What happens under abuse.** What is enforced in code, what can only be bought at the edge, and the gaps stated rather than glossed. |
| [`../SECURITY.md`](../SECURITY.md) | **How to report a vulnerability**, and what LUME does not protect you from. |

`assets/` holds images referenced from these pages and from the README.

Security findings — what was found, what was fixed, what is still open — live in
a separate private repository, not here. That separation is deliberate: this folder
describes how the system works, and that one records where it fell short.
