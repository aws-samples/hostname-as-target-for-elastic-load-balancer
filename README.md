## Elastic Load Balancer: Using hostname as a target

Elastic Load Balancing automatically distributes incoming application traffic across multiple targets, such as Amazon EC2 instances, containers, IP addresses, and Lambda functions. It can handle the varying load of your application traffic in a single Availability Zone or across multiple Availability Zones. Elastic Load Balancing offers three types of load balancers that all feature the high availability, automatic scaling, and robust security necessary to make your applications fault tolerant:

* **Application Load Balancer:** Best suited for load balancing of HTTP and HTTPS traffic and provides advanced request routing targeted at the delivery of modern application architectures, including microservices and containers. Operates at Layer 7 of Open System Interconnection (OSI) model.

* **Network Load Balancer:** Best suited for load balancing of Transmission Control Protocol (TCP), User Datagram Protocol (UDP) and Transport Layer Security (TLS) traffic where extreme performance is required. Operates at Layer 4 of OSI model.

* **Classic Load Balancer:** Provides basic load balancing across multiple Amazon EC2 instances and operates at both the request level and connection level. Classic Load Balancer is intended for applications that were built within the EC2-Classic network. Today applications are architected on EC2-VPC network and use either Application Load Balancer or Network Load Balancer.

Elastic Load Balancer (ELB), as describe above, do no support Fully Qualified Domain Name (FQDN) as targets. This repository describes solution that uses AWS Lambda (Lambda) to add FQDN as target for Elastic Load Balancer.

You create an ELB with target group of type ip. Once ELB is created, you will deploy this Lambda. Lambda periodically resolves the target FQDN and registers/deregisters IP addresses as targets from a target group. **For more information,refer to blog:[Hostname-as-Target for Newtork Load Balancer](https://insertbloglink)**

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

