#!/usr/bin/env python3
"""
DNS Checker Script

This script checks DNS records for a given domain, including A records and nameservers.
It can use a specified DNS resolver if provided.
"""

import socket
import argparse
import json
import dns.exception
import dns.resolver
import tldextract


def validate_main_domain(domain):
    """
    Validates if the given domain is a main domain (i.e., it does not have a subdomain).

    Args:
        domain (str): The domain name to validate.

    Returns:
        bool: True if the domain is a main domain, False if it has a subdomain.
    """

    extracted_domain = tldextract.extract(domain)
    if extracted_domain.suffix:
        if extracted_domain.subdomain:
            return False
        return True
    raise ValueError(f"{domain} is not a valid domain.")

def check_domain_record(domain, resolver_ip=None):
    """
    Check the DNS A record for a given domain.

    Args:
        domain (str): The domain name to resolve.
        resolver_ip (str, optional): The IP address of the DNS resolver to use. Defaults to None.

    Returns:
        str: A message indicating the result of the DNS resolution.

    Raises:
        dns.resolver.NXDOMAIN: If the domain does not exist.
        dns.resolver.Timeout: If the DNS query times out.
        dns.resolver.NoNameservers: If no nameservers are available.
        dns.exception.DNSException: For any other DNS-related errors.
    """
    resolver = dns.resolver.Resolver()
    if resolver_ip:
        resolver.nameservers = [socket.gethostbyname(resolver_ip)]
    try:
        answers = resolver.resolve(domain, 'A')
        record = [str(rdata) for rdata in answers]
        return f'{domain} has address {record}'
    except dns.resolver.NXDOMAIN:
        return f'{domain} does not exist.'
    except dns.resolver.Timeout:
        return f'Timeout while resolving {domain}.'
    except dns.resolver.NoNameservers:
        return f'No nameservers available for {domain}.'
    except dns.exception.DNSException as e:
        return f'A DNS error occurred: {e}'

def check_domain_nameservers(domain, resolver_ip=None):
    """
    Check the nameservers for a given domain.

    Args:
        domain (str): The domain name to check.
        resolver_ip (str, optional): The IP address of the DNS resolver to use. Defaults to None.

    Returns:
        str: A JSON string containing the domain and its nameservers,
        or an error message if the domain cannot be resolved.

    Raises:
        dns.resolver.NXDOMAIN: If the domain does not exist.
        dns.resolver.Timeout: If the query times out.
        dns.resolver.NoNameservers: If no nameservers are available for the domain.
        dns.exception.DNSException: For any other DNS-related errors.
    """
    resolver = dns.resolver.Resolver()
    if resolver_ip:
        resolver.nameservers = [socket.gethostbyname(resolver_ip)]
    try:
        answers = resolver.resolve(domain, 'NS')
        nameservers = [str(rdata) for rdata in answers]
        return json.dumps({'domain': domain, 'nameservers': nameservers})
    except dns.resolver.NXDOMAIN:
        return f'{domain} does not exist.'
    except dns.resolver.Timeout:
        return f'Timeout while resolving {domain}.'
    except dns.resolver.NoNameservers:
        return f'No nameservers available for {domain}.'
    except dns.exception.DNSException as e:
        return f'An error occurred: {e}'

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Check DNS records for a domain.')
    parser.add_argument('domain', help='The domain to check.')
    parser.add_argument('--resolver', help='The DNS resolver to use (optional).')

    args = parser.parse_args()

    try:
        if not validate_main_domain(args.domain):
            dom = tldextract.extract(args.domain)
            domain_name = dom.registered_domain
            print(f"{args.domain} is a subdomain of {domain_name}")
        else:
            domain_name = args.domain

        result = check_domain_nameservers(domain_name, args.resolver)
        domain_nameserver = json.loads(result)
        if args.resolver:
            combined_nameservers = domain_nameserver['nameservers'] + [args.resolver]
        else:
            combined_nameservers = domain_nameserver['nameservers']

        for ns in combined_nameservers:
            print(f'Using nameserver {ns}: {check_domain_record(args.domain, ns)}')

    except (json.JSONDecodeError, dns.exception.DNSException, socket.gaierror) as e:
        print(f'An error occurred: {e}')
