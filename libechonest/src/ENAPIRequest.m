//
//  ENAPIRequest.m
//  libechonest
//
//  Copyright (c) 2011, tapsquare, llc. (http://www.tapsquare.com, art@tapsquare.com)
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//   * Neither the name of the tapsquare, llc nor the names of its contributors
//     may be used to endorse or promote products derived from this software
//     without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL TAPSQUARE, LLC. BE LIABLE FOR ANY
//  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#import "ENAPIRequest.h"

#import "ENAPI_utils.h"
#import "ENAPI.h"
#import "ENSigner.h"
#import "NSObject+SBJSON.h"
//#import "ASIHTTPRequest.h"
#import "SBJsonParser.h"

//#define DEBUGLOG 1

@interface ENAPIRequest()
{
    NSURLResponse *_httpresponse;
    NSError *_nserror;
    NSMutableData *_receivedData;
    NSURLConnection *_theConnection;
    BOOL _completed;
    NSString *responseString;
}
- (void)_prepareToStart;
- (NSString *)_constructURL;
- (NSInteger)_generateTimestamp;
- (NSString *)_generateNonce:(NSInteger)timestamp;
- (NSString *)_constructBaseSignatureForOAuth;
- (void)_includeOAuthParams;

@property (strong) NSMutableURLRequest *request;
@property (strong,readwrite) NSMutableDictionary *params;
@property (strong) NSDictionary *_responseDict;
@property (assign) BOOL isAPIRequest;
@property (strong) NSString *analysisURL;
@end

@implementation ENAPIRequest
@synthesize delegate, response, _responseDict, endpoint;
@synthesize request, params;
@synthesize userInfo;
@synthesize isAPIRequest;
@synthesize analysisURL;

+ (ENAPIRequest *)requestWithEndpoint:(NSString *)endpoint_ {
    return [[ENAPIRequest alloc] initWithEndpoint:endpoint_];
}

+ (ENAPIRequest *)requestWithAnalysisURL:(NSString *)url_ {
    return [[ENAPIRequest alloc] initWithAnalysisURL:url_];
}

- (ENAPIRequest *)initWithEndpoint:(NSString *)endpoint_ {
    self = [super init];
    if (self) {
        CHECK_API_KEY
        self.isAPIRequest = YES;
        endpoint = endpoint_;
        self.params = [NSMutableDictionary dictionaryWithCapacity:4];
        [self.params setValue:[ENAPI apiKey] forKey:@"api_key"];
        [self.params setValue:@"json" forKey:@"format"];
        if ([ENAPI isSecuredEndpoint:endpoint]) {
            // fail fast is consumer key & secret missing
            CHECK_OAUTH_KEYS
        }
    }
    return self;
}

- (ENAPIRequest *)initWithAnalysisURL:(NSString *)url {
    self = [super init];
    if (self) {
        CHECK_API_KEY
        self.isAPIRequest = NO;
        self.analysisURL = url;
        self.params = [NSMutableDictionary dictionaryWithCapacity:4];
    }
    return self;    
}


- (void)startSynchronous {
    [self _prepareToStart];
    NSURLResponse *_response;
    NSError *_error;
    NSData *data = [NSURLConnection sendSynchronousRequest:request returningResponse:&_response error:&_error];
    _httpresponse = _response;
    _nserror = _error;
    
    responseString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
#ifdef DEBUGLOG
    NSLog(@"received %@", responseString);
#endif
    _completed = YES;
    [self requestFinished:_httpresponse];

}

- (void)startAsynchronous {
    [self _prepareToStart];
    _theConnection=[[NSURLConnection alloc] initWithRequest:request delegate:self];
}

- (void)setValue:(id)value forParameter:(NSString *)param {
    [self.params setValue:value forKey:param];
}

- (void)setIntegerValue:(NSInteger)value forParameter:(NSString *)param {
    [self.params setValue:[NSNumber numberWithInteger:value] forKey:param];
}

- (void)setFloatValue:(float)value forParameter:(NSString *)param {
    [self.params setValue:[NSNumber numberWithFloat:value] forKey:param];
}

- (void)setBoolValue:(BOOL)value forParameter:(NSString *)param {
    [self.params setValue:[NSNumber numberWithBool:value] forKey:param];
}

- (void)cancel {
    [_theConnection cancel];
}

- (BOOL)complete {
    return _completed;
}

#pragma mark - Properties

- (NSDictionary *)response {
    if (nil == _responseDict) {
        NSDictionary *dict = [responseString JSONValue];
        _responseDict = dict;
    }
    return _responseDict;
}

- (NSString *)responseString {
    return responseString;
}

- (NSInteger)responseStatusCode {
    NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)_httpresponse;
    return [httpResponse statusCode];
}

- (NSError *)error {
    return _nserror;
}

- (NSUInteger)echonestStatusCode {
    return [[self.response valueForKeyPath:@"response.status.code"] intValue];
}

- (NSString *)echonestStatusMessage {
    return [self.response valueForKeyPath:@"response.status.message"];
}

- (NSURL *)requestURL {
    return self.request.URL;
}

#pragma mark - ASIHTTPRequestDelegate Methods

- (void)requestFinished:(NSURLResponse *)request {
    if ([delegate respondsToSelector:@selector(requestFinished:)]) {
        [delegate requestFinished:self];
    }
}

- (void)requestFailed:(NSURLResponse *)request {
    if([delegate respondsToSelector:@selector(requestFailed:)]) {
        [delegate requestFailed:self];
    }
}

#pragma mark - Private Methods

- (void)_prepareToStart {
    NSMutableURLRequest *_request = [[NSMutableURLRequest alloc] init];
    if (nil != self.analysisURL) {
        [_request setURL:[NSURL URLWithString:self.analysisURL]]; // Assumes you have created an NSURL * in "myURL"

    } else {
        // add OAuth parameter if we're hitting a secured endpoint
        if ([ENAPI isSecuredEndpoint:self.endpoint]) {
            [self _includeOAuthParams];
        }
        [_request setURL: [NSURL URLWithString:[self _constructURL]]];
    }
    [_request setHTTPMethod:@"GET"];
    [_request setValue:@"application/json" forHTTPHeaderField:@"content-type"];
    _receivedData = [NSMutableData data];
    _completed = NO;
    _httpresponse = nil;
    _nserror = nil;
    self.request = _request;
}

- (NSString *)_constructURL {
    NSString *ret = [NSString stringWithFormat:@"%@%@?%@", ECHONEST_API_URL, self.endpoint, [self.params enapi_queryString]];
    return ret;
}

- (NSInteger)_generateTimestamp {
    NSDate *now = [[NSDate alloc] init];
    NSTimeInterval timestamp = [now timeIntervalSince1970];
    return (NSInteger)timestamp;
}

- (NSString *)_generateNonce:(NSInteger)timestamp {
    NSString *tmp = [[NSString alloc] initWithFormat:@"%d", timestamp];
    NSData *nonceData = [tmp dataUsingEncoding:NSUTF8StringEncoding];
    NSString *nonce = [nonceData enapi_MD5];
    return nonce;
}

- (NSString *)_constructBaseSignatureForOAuth {
    NSString *queryString = [self.params enapi_queryString];

    NSString *base_signature = [NSString stringWithFormat:@"GET&%@%@&%@",
                                ENEscapeStringForURL(ECHONEST_API_URL),
                                ENEscapeStringForURL(self.endpoint),
                                ENEscapeStringForURL(queryString)];

    NSString *signature = [ENSigner signText:base_signature
                            WithKeyAndEncode:[ENAPI sharedSecret]];

    return signature;
}

- (void)_includeOAuthParams {
    NSTimeInterval timestamp = [self _generateTimestamp];
    NSString *nonce = [self _generateNonce:timestamp];

    [self setValue:[ENAPI consumerKey] forParameter:@"oauth_consumer_key"];
    [self setIntegerValue:(NSInteger)timestamp  forParameter:@"oauth_timestamp"];
    [self setValue:@"HMAC-SHA1" forParameter:@"oauth_signature_method"];
    [self setValue:nonce forParameter:@"oauth_nonce"];
    [self setValue:@"1.0" forParameter:@"oauth_version"];

    NSString *signature = [self _constructBaseSignatureForOAuth];

    [self setValue: signature forParameter:@"oauth_signature"];
}

#pragma NSUrlConnectionDelegate


- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)_response
{
    // This method is called when the server has determined that it
    // has enough information to create the NSURLResponse.
    // It can be called multiple times, for example in the case of a
    // redirect, so each time we reset the data.
    // receivedData is an instance variable declared elsewhere.
    [_receivedData setLength:0];
    _httpresponse = _response;
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    // Append the new data to receivedData.
    // receivedData is an instance variable declared elsewhere.
    [_receivedData appendData:data];
}

- (void)connection:(NSURLConnection *)connection
  didFailWithError:(NSError *)error
{
    // inform the user
    NSLog(@"Connection failed! Error - %@ %@",
          [error localizedDescription],
          [[error userInfo] objectForKey:NSURLErrorFailingURLStringErrorKey]);
    _completed = YES;
    [self requestFailed:_httpresponse];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    // do something with the data
    // receivedData is declared as a method instance elsewhere
#ifdef DEBUGLOG
    NSLog(@"Succeeded! Received %d bytes of data",[receivedData length]);
#endif
    responseString = [[NSString alloc] initWithData:_receivedData encoding:NSUTF8StringEncoding];
    SBJsonParser *jsonParser = [[SBJsonParser alloc] init];
#ifdef DEBUGLOG
    NSLog(@"received %@", responseString);
#endif
    _completed = YES;
    [self requestFinished:_httpresponse];
}

-(NSURLRequest *)connection:(NSURLConnection *)connection
            willSendRequest:(NSURLRequest *)request
           redirectResponse:(NSURLResponse *)redirectResponse
{
    NSURLRequest *newRequest = request;
    if (redirectResponse) {
        newRequest = nil;
    }
    return newRequest;}

-(NSCachedURLResponse *)connection:(NSURLConnection *)connection
                 willCacheResponse:(NSCachedURLResponse *)cachedResponse
{
    return nil;
}




@end
