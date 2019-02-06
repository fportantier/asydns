
import boto3

class Route53Backend():

    def __init__(self, config):
        """ inicializa la API de registry
            se le pasa la config, para que pueda tomar credenciales, dominio, etc
        """

        self.config = config

        required = ['aws_id', 'aws_secret', 'route53_zone_id']
        missing = [ m for m in required if m not in self.config.keys() ]

        if missing:
            raise Exception('InvalidConfig', 'Missing required values {}'.format(','.join(missing)))

        self.client = boto3.client('route53',
            aws_access_key_id=self.config['aws_id'],
            aws_secret_access_key=self.config['aws_secret']
        )

        response = self.client.get_hosted_zone(Id='Z1AY21OJ6IQZD4')
        self.hosted_zone = response['HostedZone']

        if self.hosted_zone['Name'] != self.config['domain']:
            raise Exception('InvalidConfig', 'Config domain ({}) and hosted zone name ({}) are diferent'.format(
                self.hosted_zone['Name'],
                self.config['domain']
            ))


    def revoke(self, registry):
        """ crea el registro r-{hash}.{domain} y elimina el registro r-{hash}.domain """

        fqdn = registry + '.' + self.config['domain']
        current = self.check(registry)

        if current['status'] == 'revoked':
            return { 'status' : 'revoked', 'name' : fqdn }

        if current['status'] == 'registered':
            response = self.client.change_resource_record_sets(
                HostedZoneId=self.config['route53_zone_id'],
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'DELETE',
                            'ResourceRecordSet': {
                                'Name': registry + '.' + self.config['domain'],
                                'Type': 'A',
                                'TTL': 300,
                                'ResourceRecords': [
                                    {
                                        'Value': current['address'],
                                    },
                                ],
                            }
                        },
                    ]
                }
            )

        response = self.client.change_resource_record_sets(
            HostedZoneId=self.config['route53_zone_id'],
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': 'r-' + registry + '.' + self.config['domain'],
                            'Type': 'A',
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': '127.0.0.1',
                                },
                            ],
                        }
                    },
                ]
            }
        )

        return { 'status' : 'revoked', 'name' : fqdn }


    def update(self, registry, ip):
        """ usa registry_check para si no esta revocado, si no lo esta, actualiza el registro {hash}.domain """

        response = self.client.change_resource_record_sets(
            HostedZoneId=self.config['route53_zone_id'],
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': registry + '.' + self.config['domain'],
                            'Type': 'A',
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': ip,
                                },
                            ],
                        }
                    },
                ]
            }
        )


    def check(self, registry):
        """ indica si un registro esta revocado y, si no lo esta, cual es la IP actual """

        fqdn = registry + '.' + self.config['domain']
        rfqdn = 'r-' + fqdn

        response_rfqdn = self.client.test_dns_answer(
            HostedZoneId=self.config['route53_zone_id'],
            RecordName=rfqdn,
            RecordType='A',
        )

        if response_rfqdn['RecordData']:
            return { 'status' : 'revoked', 'name' : fqdn }

        response_fqdn = self.client.test_dns_answer(
            HostedZoneId=self.config['route53_zone_id'],
            RecordName=fqdn,
            RecordType='A',
        )

        if response_fqdn['RecordData']:
            return { 'status' : 'registered' , 'name' : fqdn, 'address' : response_fqdn['RecordData'][0]}
        else:
            return { 'status' : 'non-registered', 'name' : fqdn }


if __name__ == '__main__':

    import json
    with open('/home/f/.asydns/config.json') as config_file:
        backend = Route53Backend(json.load(config_file))

    from time import sleep

    print('query')
    tocheck = 'abcdefgh'
    print(backend.check(tocheck))

    print('update to 4.4.4.')
    backend.update(tocheck, '4.4.4.4')
    sleep(5)

    print('query')
    print(backend.check(tocheck))

    print('revoke')
    print(backend.revoke(tocheck))
    sleep(5)

    print('query')
    print(backend.check(tocheck))


    #backend.update('abcde', '9.9.9.9')
