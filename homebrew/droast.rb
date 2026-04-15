class Droast < Formula
  desc "Dockerfile linter with personality"
  homepage "https://github.com/immanuwell/dockerfile-roast"
  version "1.0.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/immanuwell/dockerfile-roast/releases/download/1.0.1/droast-macos-arm64"
      sha256 "ca6bf74b8a93d96588ef33392c877294bd2725175b29dacc90ae301828f0ce1b"
    end
    on_intel do
      url "https://github.com/immanuwell/dockerfile-roast/releases/download/1.0.1/droast-macos-x86_64"
      sha256 "7e2c2704cff1a69d6cd3f0d33897b04fcf6ab07a36e239714531ede4cdb8e2cf"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/immanuwell/dockerfile-roast/releases/download/1.0.1/droast-linux-arm64"
      sha256 "3c3024b2d576646fdca6c7b100cd843889164f0f48d862b54de7382ea5b5706f"
    end
    on_intel do
      url "https://github.com/immanuwell/dockerfile-roast/releases/download/1.0.1/droast-linux-x86_64"
      sha256 "98c2e9050f655cb1674c8271c958b2114a060306cbd002adc8199cd26196173e"
    end
  end

  def install
    # Release assets are bare binaries named droast-<platform>; rename to droast.
    downloaded = Dir["droast-*"].first
    chmod 0755, downloaded
    bin.install downloaded => "droast"
  end

  test do
    system bin/"droast", "--version"
  end
end
