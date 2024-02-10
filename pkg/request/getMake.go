package request


import (

	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)


var (
	requestPool = sync.Pool{
		New: func() interface{} {
			return new(http.Request)
		},
	}

	responsePool = sync.Pool{
		New: func() interface{} {
			return new(http.Response)
		},
	}
)


func makeRequest(urlStr, word string, results chan<- string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer func() {
		<-semaphore // release semaphore
		wg.Done()
	}()

	fullURL := fmt.Sprintf("%s/%s", urlStr, word)

	startTime := time.Now()

	// Create an HTTP client with a timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Reuse http.Request and http.Response using sync.Pool
	request := acquireRequest()
	defer releaseRequest(request)
	request.URL, _ = url.Parse(fullURL)

	response := acquireResponse()
	defer releaseResponse(response)

	// Make the HTTP request
	resp, err := client.Do(request)
	if err != nil {
		results <- fmt.Sprintf("Error making request to %s: %v", fullURL, err)
		return
	}
	defer resp.Body.Close()

	elapsedTime := time.Since(startTime)

	result := fmt.Sprintf("URL: %s, Word: %s, Status: %d, Time: %v", urlStr, word, resp.StatusCode, elapsedTime)
	results <- result
	fmt.Println(result)
}



// Pool for http.Request

func acquireRequest() *http.Request {
	return requestPool.Get().(*http.Request)
}

func releaseRequest(req *http.Request) {
	req.URL = nil
	requestPool.Put(req)
}

// Pool for http.Response


func acquireResponse() *http.Response {
	return responsePool.Get().(*http.Response)
}

func releaseResponse(resp *http.Response) {
	responsePool.Put(resp)
}