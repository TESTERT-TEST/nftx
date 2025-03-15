![DARK Header](https://github.com/dark-sergei/dark/blob/main/doc/logo-dark.png "DARK Header")

## DARK Resources
- DARK Website: [https://dark.pw](https://dark.pw)
- DARK Explorer: [Invitation](https://explorer.dark.pw)
- DARK Email: [support@dark.pw](mailto:support@dark.pw)

## DARK Blockchain Specifics

- Block Time: 60 seconds
- Starting Block Reward: 1 DARK
- Mining : 50% PoW |50% PoS
- Mining Algorithm: Equihash 200,9

## DARK core
This repository hosts the DARK core blockchain software that is required to host all Komodo-based blockchains used by the [DARK Platform](https://dark.pw/).

DARK is powered by the [Komodo Platform](https://komodoplatform.com/en), and contains code enhancements from the [Tokel Platform](https://github.com/TokelPlatform/tokel).

## List of DARK Technologies
- All technologies from the main Komodo Platform codebase, such as:
  - Delayed Proof of Work (dPoW) - Additional security layer and Komodo's own consensus algorithm
  - zk-SNARKs - Komodo Platform's privacy technology for shielded transactions (however, it is unused and inaccessible in any of Vleppo's chains)
  - CC - Custom Contracts to realize UTXO-based "smart contract" logic on top of blockchains
- Enhancements inherited from the Tokel Platform codebase, such as:
  - Improvements to the Tokens & Assets CCs
  - Improvements to Komodo's nSPV technology. nSPV is a super-lite, next-gen SPV technology gives users the ability to interact with their tokens in a decentralized & trust-less fashion on any device, without the inconvenience and energy cost of downloading the entire blockchain.
- Agreements CC, a Komodo Custom Contract allowing fully on-chain digital contract creation & management
- Token Tags CC, a Komodo Custom Contract enabling amendable data logs attached to existing Tokens


#### Dependencies
```shell
#The following packages are needed:
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool ncurses-dev unzip git zlib1g-dev wget curl bsdmainutils automake cmake clang ntp ntpdate nano -y
```

#### Linux
```shell
git clone https://github.com/dark-sergei/dark --branch main --single-branch
cd dark
./zcutil/fetch-params.sh
./zcutil/build.sh -j$(expr $(nproc) - 1)
#This can take some time.
```

#### OSX
Ensure you have [brew](https://brew.sh/) and Command Line Tools installed.

```shell
# Install brew
/bin/bash -c "$(curl -fSSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Install Xcode, opens a pop-up window to install CLT without installing the entire Xcode package
xcode-select --install
# Update brew and install dependencies
brew update
brew upgrade
brew tap discoteq/discoteq; brew install flock
brew install autoconf autogen automake
brew update && brew install gcc@8
brew install binutils
brew install protobuf
brew install coreutils
brew install wget
# Clone the DARK repo
git clone https://github.com/dark-sergei/dark --branch main --single-branch
cd dark
./zcutil/fetch-params.sh
./zcutil/build-mac.sh -j$(expr $(sysctl -n hw.ncpu) - 1)
# This can take some time.
```

#### Windows
The Windows software cannot be directly compiled on a Windows machine. Rather, the software must be compiled on a Linux machine, and then transferred to the Windows machine. You can also use a Virtual Machine-based installation of Debian or Ubuntu Linux, running on a Windows machine, as an alternative solution.
Use a Debian-based cross-compilation setup with MinGW for Windows and run:

```shell
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool ncurses-dev unzip git zlib1g-dev wget libcurl4-gnutls-dev bsdmainutils automake curl cmake mingw-w64 libsodium-dev libevent-dev
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
rustup target add x86_64-pc-windows-gnu

sudo update-alternatives --config x86_64-w64-mingw32-gcc
# (configure to use POSIX variant)
sudo update-alternatives --config x86_64-w64-mingw32-g++
# (configure to use POSIX variant)

git clone https://github.com/dark-sergei/dark --branch main --single-branch
cd dark
./zcutil/fetch-params.sh
./zcutil/build-win.sh -j$(expr $(nproc) - 1)
#This can take some time.
```

#### Launch DARK
Change to the DARK src directory:

```shell
cd ~/dark/src
```

Launch the DARK chain command:

```shell
./darkd &
```




You can use the RPC below to create a new address or import a privkey you currently have.

```shell
./dark-cli getnewaddress
```

```shell
./dark-cli importprivkey
```

Once you have completed this, use the validateaddress RPC to find your associated pubkey.

```shell
./dark-cli validateaddress *INSERTYOURADDRESSHERE*
```

Once you have written down your pubkey, stop the blockchain daemon.

```shell
cd ~/dark/src
./dark-cli stop
```

Wait a minute or so for the blockchain to stop, then relaunch the blockchain with the command below. Please remove the ** and replace them with the pubkey of the address you imported.

```shell
cd ~/dark/src
./darkd -pubkey=**YOURPUBKEYHERE** &
```

You are now ready to use the DARK software to its fullest extent.




## License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
