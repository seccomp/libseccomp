The libseccomp Release Process
===============================================================================
https://github.com/seccomp/libseccomp

This is the process that should be followed when creating a new libseccomp
release.

#### 1. Verify that all issues assigned to the release milestone have been resolved

  * https://github.com/seccomp/libseccomp/milestones

#### 2. Verify that the syntax/style meets the guidelines

	# make check-syntax

#### 3. Verify that the bundled test suite runs without error

	# ./autogen.sh
	# ./configure --enable-python
	# make check
	# (cd tests; ./regression -T live)

#### 4. Verify that the packaging is correct

	# make distcheck

#### 5. Verify that there are no outstanding defects from Coverity

	# make coverity-tarball
	<submit tarball manually>

	... or ...

	# git push -f coverity-scan
	<leverage existing Travis CI infrastructure>

#### 6. Perform any distribution test builds

  * Fedora Rawhide
  * Red Hat Enterprise Linux
  * etc.

#### 7. If any problems were found up to this point that resulted in code changes, restart the process

#### 8. Update the CREDITS file with any new contributors

	# ./doc/credits_updater > CREDITS

	... the results can be sanity checked with the following git command:

	# git log --pretty=format:"%aN <%aE>" | sort -u

#### 9. Update the CHANGELOG file with significant changes since the last release

#### 10. If this is a new major/minor release, create new 'release-X.Y' branch

	# stg branch -c "release-X.Y"

	... or ...

	# git branch "release-X.Y"

#### 11. Update the version number in configure.ac AC_INIT(...) macro

#### 12. Tag the release in the repository with a signed tag

	# git tag -s -m "version X.Y.Z" vX.Y.Z
	# git push <repo> vX.Y.Z

#### 13. Build final release tarball

	# make clean
	# ./autogen.sh
	# make dist-gzip

#### 14. Verify the release tarball in a separate directory

	<unpack the release tarball in a temporary directory>
	# ./configure --enable-python
	# make check
	# (cd tests; ./regression -T live)

#### 15. Generate a checksum for the release tarball

	# sha256sum <tarball> > libseccomp-X.Y.Z.tar.gz.SHA256SUM

#### 16. GPG sign the release tarball and checksum using the maintainer's key

	# gpg --armor --detach-sign libseccomp-X.Y.Z.tar.gz
	# gpg --clearsign libseccomp-X.Y.Z.tar.gz.SHA256SUM

#### 17. Create a new GitHub release using the associated tag; added the relevant section from the CHANGELOG file, and upload the following files

  * libseccomp-X.Y.Z.tar.gz
  * libseccomp-X.Y.Z.tar.gz.asc
  * libseccomp-X.Y.Z.tar.gz.SHA256SUM
  * libseccomp-X.Y.Z.tar.gz.SHA256SUM.asc

#### 18. Update the GitHub release notes for older releases which are now unsupported

The following Markdown text is suggested at the top of the release note, see old GitHub releases for examples.

```
***This release is no longer supported upsteam, please use a more recent release***
```
