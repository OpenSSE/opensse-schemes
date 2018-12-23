# Contributing to OpenSSE's schemes implementations

You want to help improve OpenSSE, and in particular it cryptographic toolkit. Great! Welcome onboard.
Read the following sections to know what you can do, and how you can work on this project.

Following these guidelines helps the maintainers of the project by saving their time and will allow them to help you with the possible issues you might encounter while contributing to this project.

## Getting Started

-   Make sure you have a [GitHub account](https://github.com/signup/free) (please, [use 2FA](https://help.github.com/articles/about-two-factor-authentication/)!)
-   Take a look at the following documentation ⬇️
-   See if the bug you want to report has not already been reported or fixed on the [issue page](https://github.com/OpenSSE/opensse-schemes/issues) (maybe even look in the [closed ones](https://github.com/OpenSSE/opensse-schemes/issues?q=is%3Aissue+is%3Aclosed)).

## Reporting a bug

If you have found a bug (or what you believe to be a bug), please report it! And maybe even fix it. Note that we treat differently bugs enabling security vulnerabilities and other kinds of bugs.

### Reporting a security vulnerability

If you found a vulnerability, **do NOT open an issue**. Email the [principal author](mailto:raphael_bost{at}alumni.brown.edu), and if you can encrypt your mail using his [GPG public key](http://pgp.mit.edu/pks/lookup?op=vindex&search=0xA3B23B73EEDEAA04) (this can easily be done using [Keybase](https://keybase.io/encrypt#rbost)).

A security vulnerability is a bug which might allow an attacker to access confidential data that is not his, or deny legitimate users access to their data.

### Filling an issue

For regular bugs, please open a new [issue](https://github.com/OpenSSE/opensse-schemes/issues).
In the issue, state the environnement you are working on (mainly the OS and the compiler), and carefully describe how to reproduce the bug (this is _very_ important in order to correctly locate and fix the bug).

Also, make sure to tag the issue appropriately (_e.g._ by using the bug and compilation labels if you ran into a compilation problem). Similarly, a concise, yet descriptive title helps a lot.

## Suggesting a feature or an enhancement

The philosophy of this project is to provide an implementation of some searchable encryption schemes. When possible, we rely on robust, well studied and proved instantiations of these schemes.

Theses schemes must be implemented using [OpenSSE's cryptographic toolkit](https://github.com/OpenSSE/crypto-tk) as the cryptographic abstraction layer.
No additional cryptography library should be directly used from the schemes library.

To submit a new feature or and enhancement, open an issue, choose a simple and descriptive title, and carefully describe it.

## Making changes

If you want to contribute to this project by writing some code, fork the repo and make sure you can compile the existing code by following the instructions in the [README](README.md).

You can know work on your copy of the code (working on a separate branch for your changes is a good idea). Once you are done, submit a [pull request](https://help.github.com/articles/about-pull-requests/).

The code of your PR will be reviewed by one other contributor. However, before submitting a PR, make sure that

-   [ ] All the unit tests pass, and that your contribution is covered by existing or new tests;
-   [ ] The static analysers do not raise any warning (_cf._ next section).
-   [ ] The ASan and UBSan sanitizers do not raise any error when running the unit tests (_cf._ next section).
-   [ ] The code is correctly formatted (use clang-format).

### Static analysis

In the `scripts` directory, you will find two shell scripts useful to run the [clang-tidy](http://clang.llvm.org/extra/clang-tidy/) and [cppcheck](http://cppcheck.sourceforge.net) static analysis tools.
They must be available on your machine.

cppcheck is very easy to install on Debian/Ubuntu, Fedora, or Mac OS (_cf._ the instructions on the cppcheck website).
For clang-tidy, you might have to download the last stable version of clang and LLVM from the [LLVM download page](http://releases.llvm.org/download.html).

### Dynamic analysis

It is very easy to enable the address and undefined behavior sanitizers.
Look at the `README` file to see how to enable the sanitizers.
