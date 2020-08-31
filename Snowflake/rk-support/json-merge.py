import json
import glob
import os
import datetime


def main(name="", files_to_read=None):
    date_str = datetime.date.today().strftime("%Y%m%d")
    if files_to_read is None:
        files_to_read = glob.glob("reports\\*.json")
        filename = "facebook-ad-performance_%s.json" % date_str
        file_path = "data\\%s" % filename
    else:
        filename = files_to_read[files_to_read.find("Reports") + 10:-2]
        files_to_read = "reports\\" + filename + "\\*.json"
        filename = filename + "_%s.json" % date_str
        files_to_read = glob.glob(files_to_read)
        file_path = "data\\%s" % filename
    print("files_to_read = ", files_to_read)
    print("filename = ", filename)

    result = []
    # make sure you have a reports folder , create a folder with the name reports in the same directory if its not exists.
    for f in files_to_read:
        with open(f, "rb") as infile:
            r = json.load(infile)
            if len(r) > 1:
                result.append(r)

    with open(file_path, "w") as outfile:
        json.dump(result, outfile, indent=4)

    for f in files_to_read:
        print(f)
        os.remove(f)
    return file_path, filename


if __name__ == "__main__":
    main(r"reports\\facebook-ad-reports\\")