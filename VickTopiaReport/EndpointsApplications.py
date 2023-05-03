#Author: Joaldir Rani

import requests
import json

headers = {
    'Accept': 'application/json',
    'Vicarius-Token': 'iEjmgXlUINVtggO8q1fkTYm3HMQDnniZXcVcaes1kzjbNeAU6Fs3sc0WVLXQUMgJt6K0wIkWJFgBG8X1IJIHRyaaZr3djtFkGGaid5o1q8W895sPm0obLo03WuCZzWcZtn7ECBGKwYiuID571hBe6dpiQVcHw4VsizzcN43dtNlxzXPmnbFOWJaFN6UKJcOy8JgIa2X0znBAtHcwdz0fQcpXzrS6BkgaAyMP0ZlcnNqQrAZXDD11vsldTNFAf6Y3',
}

response = requests.get(
    'https://vicarius-joaldir.vicarius.cloud/vicarius-external-data-api/aggregation/searchGroup?from=0&group=organizationEndpointPublisherProductVersionsEndpoint.endpointHash%3BpublisherProductHash%3B%3E%3BorganizationEndpointPublisherProductVersionsProduct.productName.raw%3BorganizationEndpointPublisherProductVersionsPublisher.publisherName.raw&includeOriginalDoc=false&newParser=false&objectName=OrganizationEndpointPublisherProductVersions&q=organizationEndpointPublisherProductVersionsEndpoint.endpointHash%3Din%3D(060802e18725477c04ef0be83c59c506)&size=1&subAggregationLevel=0&sumLastSubAggregationBuckets=0',
    headers=headers,
)

def parseResponse(response):
    jreponse = json.loads(response)
    print(json.dumps(jreponse,indent=2))

parseResponse(response.text)



