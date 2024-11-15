# Integrity Check Bypass For COD:CW

CWHook is a proof of concept that bypasses Arxan's integrity checks, avoids detection of reverse engineering software, a plugin loader that hot reloads modules when file modifications are detected and allowing debugging software to be (somewhat) used.

The current version of CW that this PoC targets is the one Donetsk [Defcon](https://github.com/ProjectDonetsk/Defcon) supports.

MD5: 4e6af26183709d58ffb20925e76eb461

## For individuals that are only interested in bypassing the checksum checks
Check out arxan.cpp, key functions:

FixChecksum

CreateInlineAsmStub

ArxanHealingChecksum

CreateChecksumHealingStub

I would highly recommend for people that are interested to learn how this works by reading up on the bo3 [blog post](https://momo5502.com/posts/2022-11-17-reverse-engineering-integrity-checks-in-black-ops-3/) by momo5502. 
There are a few extra things that Arxan does which prevents the integrity check fixes from momo to work on Cold War. 
For that reason alone I have made a page documenting all the things I've learned from reverse engineering Arxan while working on this project.

You can read it [here](NOTES.md).

While this does circumvent the integrity checks for the most part, on very rare occasions at startup Arxan does some extra additional checks on the locations where the inline hooks are placed resulting in the program crashing. I've described the details about it in the page documenting Arxan's behavior.

## Plugin Loader
Working on Donetsk, something I did not enjoy was having to restart the game every time I wanted to do changes to functions etc.
There is a lot of development time wasted by having to wait for the game to boot up, loading into a match and then testing whether your changes worked or not.
Which is the reason why I also shipped a fully working plugin loader which hot reloads modules on recompilation.
This should ease development productivity for anyone who's interested in writing mods etc for the game.

Demonstration:

[2024-11-13 18-58-51.webm](https://github.com/user-attachments/assets/ce5414a4-193e-4350-9ef5-ba59f62fe6df)


## Credits
Software...

Blog posts...

Websites...
