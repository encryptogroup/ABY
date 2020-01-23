import xlrd
import csv
import sys, getopt


def csv_from_excel(filename,output):
    wb = xlrd.open_workbook(filename)
    sh = wb.sheet_by_index(0)
    your_csv_file = open(output, 'w')
    wr = csv.writer(your_csv_file, quoting=csv.QUOTE_ALL)

    for rownum in range(sh.nrows):
        wr.writerow(sh.row_values(rownum))

    your_csv_file.close()

# runs the csv_from_excel function:


def main(argv):
    
        filename = 'dataS1.xlsx'
        output = 'output.csv'

        
        try:
                opts, args = getopt.getopt(argv,"hf:o:",["file=","output="])
        except getopt.GetoptError:
            print 'csvConvert.py -f <file>'
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print 'csvConvert.py -f <file>'
                sys.exit()
            elif opt in ("-f", "--file"):
                loc = str(arg)
                
            elif opt in ("-o", "--output"):
                output = str(arg)
            else: 
                print('ERROR.py -f <file>')
        
        csv_from_excel(filename,output)
                    

if __name__ == "__main__":
    main(sys.argv[1:])
