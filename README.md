# Usage

Install libfap and postgresql-libs.

Copy the sample config file into your config file and fill in with your credentials.
Note: you need two separate account for packets feed and duplicates feed due to a design choice in aprsc, see [this](https://groups.google.com/g/aprsfi/c/s3GO2da9jtw/m/8beMwyU9DgAJ).

```
cp config.toml.sample config.toml

Build and run tool
```
make
./aprs_analytics
```
