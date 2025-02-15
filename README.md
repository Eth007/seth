# seth - a security-focused, hardened vulnerability scoring engine

`seth` is a "find-and-fix" vulnerability scoring engine for creating cybersecurity training exercises,
with a focus on resistance to reverse engineering. It runs on Linux systems, and is designed for use in
competitions similar to [CyberPatriot](https://www.uscyberpatriot.org/) and [eCitadel](https://ecitadel.org/).
This engine is useful in the case when competition organizers wish to stop competitors from finding answers
through reverse engineering or dynamic analysis, in an enforcable way.

## Installation
1. On a separate machine from the competition VM, clone this repository, and install the prerequisite `Pycryptodome` python package.
2. Create your checks in the `config.yaml` file on this separate machine. In the `config_example.yaml` file, there is a list of all supported checks, with comments.
3. Run `make` to build the scoring engine. The compiled executable will be placed in the `engine` file. The configuration is baked into the scoring engine, so make sure that you recompile with `make` every time a configuration file is changed.
4. Clone this repository onto the competition VM. Run `install.sh` to put the necessary files in place.
5. Move the `engine` file onto the competition VM, and place it at `/opt/scoring/engine`.
6. Run `systemctl enable ScoringEngine` and `systemctl start ScoringEngine` to set the engine up.
7. If desired, place shortcuts to the scoring report (found at `/opt/scoring/ScoringReport.html`, or at a configurable location) on the main user's desktop.

## Security model
The idea behind this engine is that the engine does not have any more information about the scored vulnerabilities than the competitor. This means that any reverse-engineering of the source, or the configuration, is cryptographically impossible to reverse back into the checks that are scored. In addition to this, the engine is resistant toward attacks that monitor system calls or file accesses, because it makes no distinction between files that are scored and files that are not scored.

This does come at a cost; many types of checks may not be supported. Most prominently, this engine does not support any check that involves a negation (think "user does not exists" or "file/program has been deleted"). Because of this, if you want a more general-purpose engine, please use a more fully-featured engine such as [aeacus](https://github.com/elysium-suite/aeacus). 

## Note
For performance reasons, the scoring only checks files located in certain directories. While this does cover a large portion of the filesystem, you may wish to include other parts of the filesystem in your scoring checks. To accomplish this, just add a line in the [`main` function](https://github.com/Eth007/seth/blob/d70d2ec1b3b84dcf082594bfddb88ad9b5468dd8/src/engine.c#L51) for that directory (or for more security, a few directories above it), with more details in the code comments.

## Contributing
I am no longer a CyberPatriot competitor, so this project may not be frequently updated. In addition to this, the code as it is may not be top quality, as it was initially designed to be a small team project. 

## Disclaimer
This project is in no way affiliated with or endorsed by the Air Force Association, University of Texas San Antonio, or the CyberPatriot program.

## Credits
Thanks to [shiversoftdev](https://github.com/shiversoftdev) for his [Magistrate](http://magistrate.shiversoft.net/) project, which was a huge inspiration behind this scoring engine.

Also, thanks to [Astro](https://github.com/Astro1779) for the project name idea, and for designing the scoring report CSS.
