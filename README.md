# clquery: SQL interface to your cloud resources

`clquery` allows you to perform live queries on your cloud resources, and use the power of SQL to combine and filter across multiple types of services and resources.

For example, you can find virtual machine instances and their image IDs that have a port open to the public Internet, for all regions of a cloud provider.

This project is inspired by [osquery](https://osquery.io/). While the goal is multi-cloud support across main services for each cloud provider, it currently supports only AWS for a few services.
