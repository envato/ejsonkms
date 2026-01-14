package ejsonkms

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDetectFormat(t *testing.T) {
	Convey("DetectFormat", t, func() {
		Convey("should detect JSON format for .ejson files", func() {
			So(DetectFormat("secrets.ejson"), ShouldEqual, FormatJSON)
			So(DetectFormat("/path/to/secrets.ejson"), ShouldEqual, FormatJSON)
			So(DetectFormat("secrets.EJSON"), ShouldEqual, FormatJSON)
		})

		Convey("should detect YAML format for .eyml files", func() {
			So(DetectFormat("secrets.eyml"), ShouldEqual, FormatYAML)
			So(DetectFormat("/path/to/secrets.eyml"), ShouldEqual, FormatYAML)
			So(DetectFormat("secrets.EYML"), ShouldEqual, FormatYAML)
		})

		Convey("should detect YAML format for .eyaml files", func() {
			So(DetectFormat("secrets.eyaml"), ShouldEqual, FormatYAML)
			So(DetectFormat("/path/to/secrets.eyaml"), ShouldEqual, FormatYAML)
			So(DetectFormat("secrets.EYAML"), ShouldEqual, FormatYAML)
		})

		Convey("should default to JSON for unknown extensions", func() {
			So(DetectFormat("secrets.json"), ShouldEqual, FormatJSON)
			So(DetectFormat("secrets.yaml"), ShouldEqual, FormatJSON)
			So(DetectFormat("secrets.txt"), ShouldEqual, FormatJSON)
			So(DetectFormat("secrets"), ShouldEqual, FormatJSON)
		})
	})
}

func TestIsYAMLFile(t *testing.T) {
	Convey("IsYAMLFile", t, func() {
		Convey("should return true for YAML extensions", func() {
			So(IsYAMLFile("secrets.eyml"), ShouldBeTrue)
			So(IsYAMLFile("secrets.eyaml"), ShouldBeTrue)
		})

		Convey("should return false for non-YAML extensions", func() {
			So(IsYAMLFile("secrets.ejson"), ShouldBeFalse)
			So(IsYAMLFile("secrets.json"), ShouldBeFalse)
			So(IsYAMLFile("secrets.yaml"), ShouldBeFalse)
		})
	})
}
