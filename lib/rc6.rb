require "rc6/version"
require "rc6/rc6"

# This (1) vs Crypt::RC6 (2)
# 20MB file, block decryption
#    user        system      total        real
# 1. 0.343000    0.016000   0.359000 (  0.358021)
# 2. 45.646000   0.015000  45.661000 ( 45.713615)
