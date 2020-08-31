from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects import user, adaccount
# optimizing the imports -sravani
# from facebook_business.adobjects import adsinsights
# from facebook_business.adobjects.business import Business
# from facebook_business.adobjects.campaign import Campaign
# import logging
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.adobjects.adreportrun import AdReportRun

import time
import re
import json
import traceback

import multiprocessing
import os
from queue import Empty
import merge_json_file
import assign_user_ads
# import s3_dump
import datetime

MAX_PROCESSES = multiprocessing.cpu_count()
# Maximum number of retries for 500 errors.
MAX_RETRIES = 5
# Maximum number of items to be sent in a single API response.
PAGE_SIZE = 100
# Directory to download the reports to.
REPORT_DOWNLOAD_DIRECTORY = r"reports\\facebook-campaign-reports\\"

my_app_id = '878935992619738'
my_app_secret = 'd00b7199b9760a6f1c5c4b86efc5f5f3'
my_access_token = 'EAAMfYzue0toBAPDOItyKgYrIgaZA6DnyEs7WMcaVYoUoYbG8JR1KJKwdmUtCzCMolTI2bdTIxeLcxScyN1lZBYQNZBuGcGfDqDdIz2onVWENZCTu90Kob6RKc44lXNVVjRdPs5veQVJQd8KPtaLZCZBIRbZCDmCVByYZCUcANBCvZBJ0hpIzhBb7L'
FacebookAdsApi.init(my_app_id, my_app_secret, my_access_token)
# my_account = AdAccount('1454288444842444')
# campaigns = my_account.get_campaigns()
# print(campaigns)

# business = Business('1454288444842444')
# insights = business.get_insights()
# print(insights)


def _get_ad_accounts() -> [adaccount.AdAccount]:
    """Retrieves the ad accounts of the user whose access token was provided and
    returns them as a list.
    Returns:
        A list of ad accounts
    """
    system_user = user.User(fbid='me')
    params = {'limit':200}
    ad_accounts = system_user.get_ad_accounts(fields=['account_id',
                                                      'business',
                                                      'name',
                                                      'created_time',
                                                      'timezone_offset_hours_utc'], params=params)
    return ad_accounts


def parse_labels(labels: [{}]) -> {str: str}:
    """Extracts labels from a string.
    Args:
        labels: Labels in the form of
                [{"id": "1", "name": "{key_1=value_1}"},
                 {"id": "2", "name": "{key_2=value_2}"}]"'
    Returns:
            A dictionary of labels with {key_1 : value_1, ...} format
    """
    labels_dict = {}
    for label in labels:
        match = re.search("{([^=]+)=(.+)}", label['name'])
        if match:
            key = match.group(1).strip().lower().title()
            value = match.group(2).strip()
            labels_dict[key] = value
    return labels_dict


def get_ad_account_ads(ad_account) -> []:
    print('get ad data for account {}'.format(ad_account['id']))
    # ad_account = AdAccount(account_id)
    ads = ad_account.get_ads(
        fields=['account_id', 'ad_review_feedback', 'adlabels', 'adset_id',
                'bid_amount', 'bid_info', 'campaign_id', 'configured_status'],
        params={'limit': 200,
                'status': ['ACTIVE',
                           'PAUSED',
                           'ARCHIVED']})
    result = []

    for ad in ads:
        dstr = str(ad)
        d = json.loads(dstr.replace("<Ad> ", "").strip())
        d['label_attributes'] = parse_labels(ad.get('adlabels', []))
        result.append(d)
    print("total ads retrieved for ad_account: %s is %s "%(ad_account['id'], len(result)))
    return result


def get_ad_account_insights(account):
    print("getting insights for account: ", account['id'])
    # account = AdAccount(account_id)
    result = []
    fields = [
            # 'date_start',
            # 'ad_id',
            # 'impressions',
            # 'actions',
            # 'spend',
            # 'action_values'
            'account_currency',
            'account_id',
            'account_name',
            'action_values',
            'actions',
            # 'activity_recency',
            # 'ad_click_actions',
            # 'ad_format_asset',
            'ad_id',
            'ad_impression_actions',
            'ad_name',
            'adset_id',
            'adset_name',
            # 'age',
            # 'age_targeting',
            # 'auction_bid',
            # 'auction_competitiveness',
            # 'auction_max_competitor_bid',
            # 'body_asset',
            'buying_type',
            # 'call_to_action_asset',
            'campaign_id',
            'campaign_name',
            # 'canvas_avg_view_percent',
            # 'canvas_avg_view_time',
            # 'catalog_segment_actions',
            # 'catalog_segment_value',
            # 'catalog_segment_value_mobile_purchase_roas',
            # 'catalog_segment_value_omni_purchase_roas',
            # 'catalog_segment_value_website_purchase_roas',
            'clicks',
            # 'comparison_node',
            'conversion_values',
            'conversions',
            # 'converted_product_quantity',
            # 'converted_product_value',
            # 'cost_per_15_sec_video_view',
            # 'cost_per_2_sec_continuous_video_view',
            # 'cost_per_action_type',
            # 'cost_per_ad_click',
            # 'cost_per_conversion',
            # 'cost_per_dda_countby_convs',
            # 'cost_per_inline_link_click',
            # 'cost_per_inline_post_engagement',
            # 'cost_per_one_thousand_ad_impression',
            # 'cost_per_outbound_click',
            # 'cost_per_store_visit_action',
            # 'cost_per_thruplay',
            # 'cost_per_unique_action_type',
            # 'cost_per_unique_click',
            # 'cost_per_unique_conversion',
            # 'cost_per_unique_inline_link_click',
            # 'cost_per_unique_outbound_click',
            # 'country',
            'cpc',
            'cpm',
            'cpp',
            'created_time',
            'ctr',
            'date_start',
            'date_stop',
            # 'dda_countby_convs',
            # 'description_asset',
            # 'device_platform',
            # 'dma',
            # 'estimated_ad_recall_rate_lower_bound',
            # 'estimated_ad_recall_rate_upper_bound',
            # 'estimated_ad_recallers_lower_bound',
            'estimated_ad_recallers_upper_bound',
            'frequency',
            # 'frequency_value',
            'full_view_impressions',
            'full_view_reach',
            # 'gender',
            # 'gender_targeting',
            # 'hourly_stats_aggregated_by_advertiser_time_zone',
            # 'hourly_stats_aggregated_by_audience_time_zone',
            # 'image_asset',
            # 'impression_device',
            'impressions',
            # 'impressions_dummy',
            # 'inline_link_click_ctr',
            # 'inline_link_clicks',
            # 'inline_post_engagement',
            # 'instant_experience_clicks_to_open',
            # 'instant_experience_clicks_to_start',
            # 'instant_experience_outbound_clicks',
            # 'labels',
            # 'link_url_asset',
            'location',
            # 'media_asset',
            'mobile_app_purchase_roas',
            'objective',
            # 'outbound_clicks',
            # 'outbound_clicks_ctr',
            # 'platform_position',
            # 'product_id',
            # 'publisher_platform',
            'purchase_roas',
            'qualifying_question_qualify_answer_rate',
            'reach',
            # 'region',
            # 'rule_asset',
            'social_spend',
            'spend',
            'store_visit_actions',
            # 'title_asset',
            # 'unique_actions',
            # 'unique_clicks',
            # 'unique_conversions',
            # 'unique_ctr',
            # 'unique_inline_link_click_ctr',
            # 'unique_inline_link_clicks',
            # 'unique_link_clicks_ctr',
            # 'unique_outbound_clicks',
            # 'unique_outbound_clicks_ctr',
            # 'unique_video_view_15_sec',
            # 'updated_time',
            'video_15_sec_watched_actions',
            'video_30_sec_watched_actions',
            # 'video_asset',
            'video_avg_time_watched_actions',
            'video_continuous_2_sec_watched_actions',
            'video_p100_watched_actions',
            'video_p25_watched_actions',
            'video_p50_watched_actions',
            'video_p75_watched_actions',
            'video_p95_watched_actions',
            'video_play_actions',
            'video_play_curve_actions',
            'video_play_retention_0_to_15s_actions',
            'video_play_retention_20_to_60s_actions',
            'video_play_retention_graph_actions',
            'video_time_watched_actions',
            # 'website_ctr',
            # 'website_purchase_roas',
            # 'wish_bid',
            # 'campaign_id', 'unique_clicks', 'impressions',
            # 'account_id', 'campaign_id',
            # 'cost_per_inline_post_engagement',
            # # 'inline_post_engagement',
            # 'conversion_rate_ranking', 'conversion_values',
            # 'conversions', 'cost_per_conversion',
            # # 'cost_per_unique_conversion',
            # 'full_view_reach',
            # # 'unique_conversions',
            # 'cpc','clicks','inline_link_clicks','instant_experience_clicks_to_open',
            # 'instant_experience_clicks_to_start', 'instant_experience_outbound_clicks','outbound_clicks_ctr',
            # 'unique_clicks','unique_inline_link_clicks','unique_inline_link_clicks', 'unique_link_clicks_ctr',
            # 'unique_outbound_clicks', 'unique_outbound_clicks_ctr', 'full_view_impressions', 'impressions',
            # 'campaign_id', 'campaign_name', 'conversions', 'cost_per_15_sec_video_view', 'cost_per_2_sec_continuous_video_view',
            # 'cost_per_action_type', 'cost_per_ad_click', 'cost_per_conversion', 'cost_per_dda_countby_convs',
            # 'cost_per_estimated_ad_recallers', 'cost_per_inline_link_click', 'cost_per_inline_post_engagement',
            # 'cost_per_one_thousand_ad_impression', 'cost_per_outbound_click', 'cost_per_store_visit_action',
            # 'cost_per_thruplay',
            # 'cost_per_unique_action_type',
            # 'cost_per_unique_click',
            # 'cost_per_unique_inline_link_click', 'cost_per_unique_outbound_click', 'cpm', 'cpp', 'created_time'

    ]
    start_date = datetime.datetime.today() - datetime.timedelta(days=1)
    start_date = start_date.strftime('%Y-%m-%d')
    end_date = datetime.datetime.today().strftime('%Y-%m-%d')
    params = {
        # https://developers.facebook.com/docs/marketing-api/insights/action-breakdowns
        'action_breakdowns': ['action_type'],
        # https://developers.facebook.com/docs/marketing-api/insights/breakdowns
        'breakdowns': ['impression_device'],
        'level': 'campaign',
        'limit': 1000,
        'time_range': {'since': start_date,
                       'until': end_date},
        # By default only ACTIVE campaigns get considered.
        'filtering': [{
            'field': 'ad.effective_status',
            'operator': 'IN',
            'value': ['ACTIVE',
                      'PAUSED',
                      'PENDING_REVIEW',
                      'DISAPPROVED',
                      'PREAPPROVED',
                      'PENDING_BILLING_INFO',
                      'CAMPAIGN_PAUSED',
                      'ARCHIVED',
                      'ADSET_PAUSED']}]}

    # https://developers.facebook.com/docs/marketing-api/insights/best-practices
    # https://developers.facebook.com/docs/marketing-api/asyncrequests/
    async_job = account.get_insights(fields=fields, params=params, is_async=True)
    async_job.api_get()
    while async_job[AdReportRun.Field.async_percent_completion] < 100 or async_job[
        AdReportRun.Field.async_status] != 'Job Completed':
        time.sleep(1)
        async_job.api_get()
    time.sleep(1)

    ad_insights = async_job.get_result()

    for insight in ad_insights:
        dstr = str(insight)
        d = json.loads(dstr.replace("<AdsInsights> ", "").strip())
        result.append(d)
    print("insights count: ", len(result))
    return result
        # 'date_start',
    #           'ad_id',
    #           'impressions',
    #           'actions',
    #           'spend',
    #           'action_values']
    # params = {
    #     'level': 'campaign',
    #     'date_preset': 'last_30d',
    # }

    # Commenting this below code as it is duplicate of above code - by Sravani
    #insights = account.get_insights(fields=fields, params=params, is_async=True)
    # for insight in insights:
    #dstr = str(insights)
    #d = json.loads(dstr.replace("<AdReportRun> ", "").strip())
    #result.append(d)
    #print("insights count: ", len(result))
    #return result


def _DownloadReport(process_id, report_download_directory,  ad_account_dict):
    try:
        filepath = os.path.join(report_download_directory,
                                'ad_performance_%s.json' % ad_account_dict['id'])
        ad_account = AdAccount(ad_account_dict['id'])
        # ad_data = get_ad_account_ads(ad_account)
        # ad_account_dict['ads_data'] = ad_data
        ad_account_dict['insights'] = get_ad_account_insights(ad_account)
        f = open(filepath, 'w')
        json.dump(ad_account_dict, f, indent=4)
        f.close()
        # Changed the return code to correct - Sravani
        return True, {'account_id':ad_account_dict['id']}
    except Exception as ex:
        traceback.print_exc()
        # Changed the return code to correct - Sravani
        return True, {'account_id':ad_account_dict['id'], "error":str(ex)}


class ReportWorker(multiprocessing.Process):

  def __init__(self,input_queue, success_queue, failure_queue):
    """Initializes a ReportWorker.

    Args:
      report_download_directory: A string indicating the directory where you
        would like to download the reports.
      report_definition: A dict containing the report definition that you would
        like to run against all customer IDs in the input_queue.
      input_queue: A Queue instance containing all of the customer IDs that
        the report_definition will be run against.
      success_queue: A Queue instance that the details of successful report
        downloads will be saved to.
      failure_queue: A Queue instance that the details of failed report
        downloads will be saved to.
    """
    super(ReportWorker, self).__init__()
    self.report_download_directory = REPORT_DOWNLOAD_DIRECTORY
    self.input_queue = input_queue
    self.success_queue = success_queue
    self.failure_queue = failure_queue

  def run(self):
    while True:
      try:
        ad_account = self.input_queue.get(timeout=0.01)
      except Empty:
        break
      result = _DownloadReport(self.ident, self.report_download_directory, ad_account)
      print("retrieved account_data %s, result is: %s"%(ad_account['id'], result))
      (self.success_queue if result[0] else self.failure_queue).put(result[1])
      print("########## Done with process : ", self.ident, "  account: ", ad_account['id']


def main():
    # ADD user to ad accounts
    assign_user_ads.main()

    input_queue = multiprocessing.Queue()
    reports_succeeded = multiprocessing.Queue()
    reports_failed = multiprocessing.Queue()

    ad_accounts = _get_ad_accounts()
    result_accounts = []
    total_ads_count = 0
    #print(ad_accounts)
    for ad_account in ad_accounts:
        # print("retrieving ads for ad_account: ", ad_account['id'])
        dstr = str(ad_account)
        d = json.loads(dstr.replace("<AdAccount> ", "").strip())
        input_queue.put(d)
        # ad_data = get_ad_account_ads(ad_account)
        # d['ads_data'] = ad_data
        # total_ads_count += len(ad_data)
        # insights = get_ad_account_insights(ad_account)
        # d['insights'] = insights
        # result_accounts.append(d)

    queue_size = input_queue.qsize()
    num_processes = min(queue_size, MAX_PROCESSES)
    print('Retrieving %d reports with %d processes:' % (queue_size, num_processes))
    # Start all the processes.
    processes = [ReportWorker(input_queue, reports_succeeded,reports_failed)
                 for _ in range(num_processes)]

    for process in processes:
        process.start()

    for process in processes:
        # 3min timeout per process increased from 1 min to 3 min - Sravani
        process.join(180)
        # Checking process is completed or not else waiting for one more min - Sravani
        while process.is_alive():
            print("process is not finished waiting for some more time")
            # waiting for one min
            time.sleep(60)
        ### Add the code to process the files after it reaches to 1000


    print('Finished downloading reports with the following results:')
    success_list = []
    while True:
        try:
            success = reports_succeeded.get(timeout=0.01)
            success_list.append(success['account_id'])
        except Empty:
            break
        # print('\tReport for account "%s" succeeded.' % success['account_id'])

    failure_list = []
    while True:
        try:
            failure = reports_failed.get(timeout=0.01)
            failure_list.append(failure)
        except Empty:
            break
        # print('\tReport failed with: "%s"' % failure)

    print("success: ", success_list)
    print("failed: ", failure_list)

    file_path, file_name = merge_json_file.main(files_to_read=REPORT_DOWNLOAD_DIRECTORY)
    date_str = datetime.date.today().strftime("%Y/%m/%d")

    # obj = s3_dump.GoogleS3Dump(
    #     # bucket_name="cmgt-dataservices-dev",
    #     # s3_file_path="testfiles/Facebook/" + date_str,
    #     # file_location=[file_path]
    #     # Maureen suggested to dump in "cmg-datalake-ingest-burt", when we need to change bucket we can change accordingly in the bucket name.
    #     # bucket_name="cmg-datalake-ingest-burt",
    #     bucket_name="cmg-datalake-ingest-facebookads-dev",
    #     s3_file_path=date_str,
    #     file_location = file_path
    # )
    # # obj.google_api_handler()
    # obj.upload_as_large_files()


if __name__ == "__main__":
    main()
