#!/usr/bin/env bash
set -e

DIR=$(dirname "$0")

# install node modules
YARN=yarn
[ -x /usr/bin/lsb_release ] && [ -n "`lsb_release -i | grep Debian`" ] && YARN=yarnpkg
$YARN install --pure-lockfile --production

# Copy admin-lte dist
mkdir -p "${DIR}/assets/dist/js" "${DIR}/assets/dist/css" && \
  cp -r "${DIR}/node_modules/admin-lte/dist/js/adminlte.min.js" "${DIR}/assets/dist/js/adminlte.min.js" && \
  cp -r "${DIR}/node_modules/admin-lte/dist/css/adminlte.min.css" "${DIR}/assets/dist/css/adminlte.min.css"

# Copy helper js
cp -r "${DIR}/custom" "${DIR}/assets"

# Copy plugins
mkdir -p "${DIR}/assets/plugins" && \
  cp -r "${DIR}/node_modules/admin-lte/plugins/jquery" \
  "${DIR}/node_modules/admin-lte/plugins/fontawesome-free" \
  "${DIR}/node_modules/admin-lte/plugins/bootstrap" \
  "${DIR}/node_modules/admin-lte/plugins/icheck-bootstrap" \
  "${DIR}/node_modules/admin-lte/plugins/toastr" \
  "${DIR}/node_modules/admin-lte/plugins/jquery-validation" \
  "${DIR}/node_modules/admin-lte/plugins/select2" \
  "${DIR}/node_modules/jquery-tags-input" \
  "${DIR}/assets/plugins/"
