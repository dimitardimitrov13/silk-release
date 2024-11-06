package common_test

import (
	"code.cloudfoundry.org/lib/common"
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"time"
)

// Mock retryable error that implements temporaryError
type mockTemporaryError struct {
	msg string
}

func (e *mockTemporaryError) Error() string   { return e.msg }
func (e *mockTemporaryError) Temporary() bool { return true }

// Mock non-retryable error that does not implement temporaryError
type mockNonRetryableError struct {
	msg string
}

func (e *mockNonRetryableError) Error() string { return e.msg }

var _ = Describe("Retry With Backoff", func() {
	var (
		callCount int
	)

	BeforeEach(func() {
		callCount = 0
	})

	Context("when function succeeds the first try", func() {
		It("returns result without retries", func() {
			fn := func() (int, error) {
				callCount++
				return 42, nil
			}

			result, err := common.RetryWithBackoff(100, 3, fn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(42))
			Expect(callCount).To(Equal(1))
		})
	})

	Context("when function fails with a non-retryable error", func() {
		It("returns the error immediately", func() {
			fn := func() (int, error) {
				callCount++
				return 0, &mockNonRetryableError{"non-retryable error"}
			}

			result, err := common.RetryWithBackoff(100, 3, fn)
			Expect(err).To(MatchError("non-retryable error"))
			Expect(result).To(Equal(0))
			Expect(callCount).To(Equal(1))
		})
	})

	Context("when function fails with a retryable error", func() {
		It("retries the function up to maxRetries times and eventually succeeds", func() {
			fn := func() (int, error) {
				callCount++
				if callCount == 3 {
					return 42, nil
				}
				return 0, &mockTemporaryError{"retryable error"}
			}

			result, err := common.RetryWithBackoff(100, 3, fn)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(42))
			Expect(callCount).To(Equal(3))
		})
	})

	Context("when the maxRetries are exhausted", func() {
		It("returns the last error", func() {
			fn := func() (int, error) {
				callCount++
				return 0, &mockTemporaryError{fmt.Sprintf("retryable error %d", callCount)}
			}

			result, err := common.RetryWithBackoff(100, 3, fn)
			Expect(err).To(MatchError(fmt.Sprintf("failed after 3 maxRetries: retryable error %d", 3)))
			Expect(result).To(Equal(0))
			Expect(callCount).To(Equal(3))
		})
	})

	Context("exponential backoff timing", func() {
		It("should do exponential backoff each retry", func() {
			start := time.Now()

			fn := func() (int, error) {
				return 0, &mockTemporaryError{msg: "temporary error"}
			}

			common.RetryWithBackoff(50, 3, fn)
			elapsed := time.Since(start)

			// 50ms * (2^0 + 2^1 + 2^2) = 350ms
			expectedTime := 350 * time.Millisecond
			Expect(elapsed).To(BeNumerically(">=", expectedTime))
		})
	})
})
