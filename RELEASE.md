# Release Guide

Keylime uses a semantic versioning process:

    Major.Minor.Patch

### Patch

When a bug fix is made:

```
v0.0.3 // Before bugfix
v0.0.4 // After bugfix
```

### Minor

When you add functionality and your code stays backwards compatible, you increase the minor component and reset the patch component to zero:

```
v0.2.4 // Before addition of new functionality
v0.3.0 // After addition of new functionality
```

### Major

When you implement changes and your code becomes backwards incompatible (e.g. API change), you increase the major component and reset the minor and patch components to zero:

```
v7.3.5 // Before implementing backwards incompatible changes
v8.0.0 // After implementing backwards incompatible changes
```

## Using semantic versions with Git

Semver is realised using git tags:

    $ git tag -a v3.0.2 -m 'Keylime version 3.0.2'

Alternatively, you can use the github UI to create a tag, at the same time as
the release.

Go to the [new release page](https://github.com/keylime/keylime/releases/new)
and  enter a Tag, provide a title (Keylime vx.x.x) and list the changes in the release,
linking to commits.

## Further reading

More details about [available here](https://github.com/semver/semver/blob/master/semver.md)
