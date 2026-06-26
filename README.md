# WebSpeare : A Deceptive Web Tarpit

**WebSpeare** is a lightweight, zero-dependency honeypot written entirely in Ruby.
Designed to enable malicious web crawlers, automated hacking tools, and
Opportunistic threat actors.

It generates constantly changing pages filled with random Shakespearean excerpts,
Fabricated error logs, and enticing false hyperlinks. A woven snare to waste time and
Resources of malicious bots!

Ideal for gathering threat intelligence in high traffic systems,
Studying automated behavior, and disrupting tools like SQLMap, BurpSuite, nikto, nuclie
And more!

## Features:
* Pure Ruby - No external or bloated dependencies!
* Dynamic page generation - Randomized content perfect for keeping bots stuck!
* Shakespearean quotes - a tasteful taunt.
* Lots of triggers - Fake links, error artifacts to lure and mislead
* Small and easy to parse - Perfect for passive defense, research and bot profiling
* Easy parsing - activity is logged cleanly in `.json` and `.log` formats (Silimar to cowrie)
* Flexible and adjustable - adjust anything you desire via simple JSON files and an HTML template
* Minimal footprint - ideal for lightweight deployments and research setups


## Reguarding AI
AI (Claude/GPT) was used in the development of WebSpeare and continues to be used in a rather silly way. </br>
I'm not very good with REGEX. But you know who is? AI! Claude/GPT and Such. Have been helpful with the development of Regex </br>
and detection rules. The core application itself, is maintained by human-code and such. </br>
And I would like to keep it this way; to prevent silly mistakes. </br>

However, I do encorage the usage of AI in the context of Fuzzing/Code auditing/Commenting (but not editing); </br>
Of Functions/Classes and Such; to prevent issues/oversights from being an issue in deployment.

