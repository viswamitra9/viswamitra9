import csv
import json


def convert_csv_json(csfile, jsfile):
    fields = ['AdGroupId', 'AllConversionRate', 'AllConversions', 'AllConversionValue', 'Criteria', 'AverageCpc',
              'AverageCpe', 'AverageCpm', 'AverageCpv', 'CampaignId', 'AveragePosition', 'CampaignName', 'Clicks',
              'ConversionRate', 'Conversions', 'ConversionValue', 'Cost', 'CostPerConversion',
              'CostPerCurrentModelAttributedConversion', 'Date', 'VideoQuartile100Rate', 'VideoQuartile25Rate',
              'VideoQuartile50Rate', 'VideoQuartile75Rate', 'AveragePosition', 'Criteria', 'Id', 'Impressions',
              'Interactions', 'Week', 'Year', 'VideoViews']
    with open(jsfile, "w",encoding='utf-8') as outfile:
        with open(csfile, newline='') as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=fields)
            # skip first too lines
            skip_line1 = next(reader)
            skip_line2 = next(reader)
            for row in reader:
                # skip last line
                if row['AdGroupId'] != 'Total':
                    json.dump(row,outfile, indent=4, sort_keys=True,ensure_ascii=False)
                    print(json.dumps(row, sort_keys=True, indent=4,ensure_ascii=False))
    outfile.close()
    csvfile.close()


convert_csv_json(jsfile='C:\\csvtojson\\test.json', csfile='C:\\csvtojson\\test.csv')
