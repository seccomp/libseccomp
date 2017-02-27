The libseccomp Release Process
===============================================================================
https://github.com/seccomp/libseccomp

This is the process that should be followed when creating a new libseccomp
release.

#### 1. Verify that the syntax/style meets the guidelines

	# make check-syntax

#### 2. Verify that the bundled test suite runs without error

	# ./autogen.sh
	# ./configure --enable-python
	# make check
	# (cd tests; ./regression -T live)

#### 3. Verify that the packaging is correct

	# make distcheck

#### 4. Verify that there are no outstanding defects from Coverity

	# make coverity-tarball
	<submit tarball manually>

	... or ...

	# git push -f coverity-scan
	<leverage existing Travis CI infrastructure>

#### 5. Perform any distribution test builds

  * Fedora Rawhide
  * Red Hat Enterprise Linux
  * etc.

#### 6. If any problems were found up to this point that resulted in code changes, start again step #1

#### 7. Update the CREDITS file with any new contributors

	# ./doc/credits_updater > CREDITS

	... the results can be sanity checked with the following git command:

	# git log --pretty=format:"%aN <%aE>" | sort -u

#### 8. Update the CHANGELOG file with significant changes since the last release

#### 9. If this is a new major/minor release, create new 'release-X.Y' branch

	# stg branch -c "release-X.Y"

	... or ...

	# git branch "release-X.Y"

#### 10. Update the version number in configure.ac AC_INIT(...) macro

#### 11. Tag the release in the repository

	# git tag -m "version X.Y.Z" vX.Y.Z
	# git push --tags

#### 12. Build final release tarball

	# make clean
	# ./autogen.sh
	# make dist-gzip

#### 13. Verify the release tarball in a separate directory

	<unpack the release tarball in a temporary directory>
	# ./configure --enable-python
	# make check
	# (cd tests; ./regression -T live)

#### 14. Generate a checksum for the release tarball

	# sha256sum <tarball> > libseccomp-X.Y.Z.tar.gz.SHA256SUM

#### 15. GPG sign the release tarball and checksum using the maintainer's key

	# gpg --armor --detach-sign libseccomp-X.Y.Z.tar.gz
	# gpg --clearsign libseccomp-X.Y.Z.tar.gz.SHA256SUM

#### 16. Create a new GitHub release using the associated tag; added the relevant section from the CHANGELOG file, and upload the following files

  * libseccomp-X.Y.Z.tar.gz
  * libseccomp-X.Y.Z.tar.gz.asc
  * libseccomp-X.Y.Z.tar.gz.SHA256SUM
  * libseccomp-X.Y.Z.tar.gz.SHA256SUM.asc
