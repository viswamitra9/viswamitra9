def open_files(start):
    return {
        'orderLines': {
            'name': 'orderLines',
            'file': open(r'C:eltoro-orderLines.csv', 'w'),
        },
        'campaigns': {
            'name': 'campaigns',
            'file': open(r'C:eltoro-campaigns.csv', 'w'),
        },
        'creatives': {
            'name': 'creatives',
            'file': open(r'C:eltoro-creatives.csv', 'w'),
            'denorm': 'orderLines',
        },
    }

for level in open_files('test'):
    print(level)