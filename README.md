# 🛸Project Goals🛸

These are snatched from the original project (_OP_), with some adjustments and amendments.
Even though the list is ordered, they are not (yet) ordered by priority, but merely to make each point adressable, as in `🛸2`.

1. provide an idiomatic rust implementation for Google APIs, which includes _type safety_ and native _async_ operations.
1. first-class documentation with cross-links and complete code-examples
1. support all API features, including downloads and resumable uploads
1. Convenient CLIs are provided on top of the API for use in shell scripts
1. _safety and resilience are built-in, allowing you to create highly available tools on top of it. For example, you can trigger retries for all operations that may temporarily fail, e.g. due to network outage._
   * **Byron thinks that** this could be naturally supported by the async ecosystem, and thus helps slim down the delegate.
1. API and CLI generation can be customized easily to overcome issues with your particular API
   * **Byron thinks that** we cannot assume to get it right for all APIs from the start unless we actually test everything ourselves. Thus if we enable people to help themselves, it will help us further down the line.
1. Built-in debugging and tracing allows to understand what's going on, and what's wrong.
   * **Byron thinks that** providing full output of requests and responses when using the CLI really helped. However, this time around there might be some more logging, using `tracing` or `log` at least. Here once again it becomes interesting to see if different systems can be supported, to allow people to tailor their experience based on their needs. `cargo features` could come a long way.
1. The code we generate defines the standard for interacting with Google services via Rust.
   * Google uses these crates! They are that good!
1. The code base is made for accepting PRs and making contributions easy
   * To stay relevant, people must contribute.
   * The original authors won't stay around forever (see [GitPython](https://github.com/gitpython-developers/GitPython))

# Learning from the past

Let's keep in mind what worked and what didn't.

## 🌈What worked well in _OP_🌈

1. **`make` to track dependencies and drive tooling**
   * Having built-in help was nice, and one go-to location to drive everything around the project
1. **Building big data models**
   * It was very helpful to have all data available in a tree
   * Merging structured data into even bigger trees helped to keep all data in easy to edit, human readable files, even with the option to pull in 'override files' to patch API descriptions as needed. The latter was used with the [Drive API](https://github.com/Byron/google-apis-rs/blob/master/etc/api/drive/v2/drive-api_overrides.yaml#L1), even though I would only add such capability on an as-needed basis.
1. **Having an off-the-shelf template engine**
   * Generating text from 'smart' files with some basic support for syntax highlighting made it quite easy to get started.
   * This was only possible through the `make` driven automation, as one would have to run multiple tools including `cargo check` to
    see if it actually worked.
1. **Performance**
   * Code generation was fast enough and could be parallelized on a per-API/CLI basis thanks to `make`.
1. **API, Docs, and CLIs**
   * I think having fully type-safe and chainable APIs was great.
   * The docs were lovely
   * The CLIs allowed to use an API almost instantly

## 🥵Issues with _OP_'s way of doing things🥵

1. **logic in templates**
   * What seemed like a huge benefit was also causing vastly difficult to read and understand templates.
   * I remember that sometimes, I worked around certain limitations of the engine, which masked what one was actually doing.
   * Separation of concerns is a good thing, but _OP_ didn't have it. The template engine transformed the data model from _discovery_
    on the fly.
1. **massive code duplication caused huge libraries**
   * Each call would be 'spelled out', and APIs came with many calls. This caused massive libraries that take a while to check and build.
   * Huge files are harder to read
1. **improper namespace handling**
   * types introduced by the API could clash with reserved names of the Rust language, or with names imported into the namespace.
   * It wasn't easy to handle names consistently in all places that needed them
1. **python and mako**
   * Even though they worked, it was another thing that had to be installed by `make`, and could just fail [for some](https://github.com/Byron/google-apis-rs/issues/234)
1. **arbitrary smartness**
   * In order to fix issues with the type system and make numbers more easily usable by converting "strings" into integers/floats, what worked in one API broke another.
1. **it's cumbersome to actually use a CLI**
   * Even though authentication was dealt with nicely for the most part, actually using APIs required them to be enabled via the developer console. From there one would download a file and deposit it in the right spot. Only then one could start using the CLI.
1. **oddly keyed login tokens stored on disk per scope**
   * due to tokens being hashed by the scope(s) they represent, chosing a different scope forced you to re-authenticate, even though another token file already included the scope you wanted.
1. **it took at least 6 weeks to get the first release on crates.io**
   * development wasn't the fastest, and I claim one was slowed down due to too much manual testing.
1. **there was no way to use the CI to test CLIs to actually interact with Google APIs**
   * This was due to API usage being bound to a person, and these credentials were nothing you would want to have lying around in a public git repository.
   * Not being able to test certain feature automatically and repeatedly takes time and reduces quality garantuees.


# Technology and Architecture Sketches

Items mentioned below ideally create a link to one of the problems they slove, e.g. `🥵2` , the project goal they support, e.g `🛸3`, or the effective thing they build on (`🌈1`).

## Toolchains

The _OP_ suffered a little from chosing Python and Mako, the latter being a template language mostly unknown to people. Less is more.
Here is the anticipated tooling. What follows is the list of tools I would add and why.

* **make**
  * I am a fan of simple makefiles, which catch dependencies between files and run a script to generate them. This served _OP_ extremely well.
  * get parallelization for free, and make transparent which programs to call and how to get work done.
  * the Makefile serves as hub keeping all commands one would run to interact with the project in any way.
* **Cargo/Rust**
  * All work should be done by a Rust binary
* **rust-fmt**
  * Definitely needed to get idiomatically looking code.
  * _OP_ didn't have it, it wasn't a real problem, but too much time was spent making things look pretty. With `rust-fmt`, templates can be optimized for maintainability, even if the output doesn't look great initially.

* **Docker (optional)** ... maybe, but probably not :D
  * For those who have none the above tooling but docker, it's easy to run something like `make interactive-docker-environment` and be dropped into shell that can run all tools and all make targets.
  * It's usually good to document the entire toolchain that way.
  * Can, and probably _should_ be used by CI to validate it works.
  * given the simplicity of the toolchain above, I'd say it truly is optional.


# Development Goals

These should optimize for allowing a pleasant developer experience, at the beginning of the project as well as things stabilize. They should support the project goals or at least not hinder them. For example, settings things up in a way that is hard to use to the average person would be in the way of allowing folks to 'easily' fix issues they encounter.

* **TDD**
  * Everything done should be driven by at least one test which can be run automatically.
  * **Byron thinks that** the _OP_ suffered from only having a few tests, and even though Rust only compiles decent quality software, by nature, certain reasoning was just in my head. _'Why is it doing this particular thing? It seems wrong'_ would be impossible to know. With TDD, there is a chance there will be a test for that. Also TDD speeds up development as validations don't have to be performed manually.
  * **Byron also thinks that** this is totally doable without breaking into sweat.