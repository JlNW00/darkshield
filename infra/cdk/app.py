"""AWS CDK stack for DarkShield deployment."""
import aws_cdk as cdk
from constructs import Construct
from aws_cdk import (
    aws_lambda as _lambda,
    aws_apigateway as apigw,
    aws_s3 as s3,
    aws_dynamodb as dynamodb,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_iam as iam,
    Duration,
    RemovalPolicy,
)

class DarkShieldStack(cdk.Stack):
    def __init__(self, scope: Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        # S3 bucket for screenshots and reports
        screenshots_bucket = s3.Bucket(
            self, "ScreenshotsBucket",
            bucket_name=f"darkshield-screenshots-{self.account}",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            cors=[s3.CorsRule(
                allowed_methods=[s3.HttpMethods.GET],
                allowed_origins=["*"],
            )],
        )

        # DynamoDB table for audit history
        audits_table = dynamodb.Table(
            self, "AuditsTable",
            table_name="darkshield-audits",
            partition_key=dynamodb.Attribute(name="audit_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="created_at", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Lambda function for API
        api_handler = _lambda.DockerImageFunction(
            self, "ApiHandler",
            code=_lambda.DockerImageCode.from_image_asset("../backend"),
            memory_size=512,
            timeout=Duration.seconds(300),
            environment={
                "SCREENSHOTS_BUCKET": screenshots_bucket.bucket_name,
                "AUDITS_TABLE": audits_table.table_name,
            },
        )

        screenshots_bucket.grant_read_write(api_handler)
        audits_table.grant_read_write_data(api_handler)

        # API Gateway
        api = apigw.LambdaRestApi(
            self, "DarkShieldApi",
            handler=api_handler,
            proxy=True,
        )

        # CloudFront for frontend
        frontend_bucket = s3.Bucket(
            self, "FrontendBucket",
            website_index_document="index.html",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        distribution = cloudfront.Distribution(
            self, "FrontendCDN",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(frontend_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            ),
            additional_behaviors={
                "/api/*": cloudfront.BehaviorOptions(
                    origin=origins.HttpOrigin(
                        f"{api.rest_api_id}.execute-api.{self.region}.amazonaws.com",
                        origin_path=f"/{api.deployment_stage.stage_name}",
                    ),
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                ),
            },
        )

        cdk.CfnOutput(self, "ApiUrl", value=api.url)
        cdk.CfnOutput(self, "CDNUrl", value=f"https://{distribution.distribution_domain_name}")
        cdk.CfnOutput(self, "ScreenshotsBucketName", value=screenshots_bucket.bucket_name)

app = cdk.App()
DarkShieldStack(app, "DarkShieldStack")
app.synth()
