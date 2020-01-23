#include <string>
#include <fstream>
#include <vector>
#include <utility> // std::pair
#include <stdexcept> // std::runtime_error
#include <sstream> // std::stringstream
#include <iostream>




void Print (const vector<int>& v){
  //vector<int> v;
  for (int i=0; i<v.size();i++){
    std::cout << v[i] << std::endl;
  }
}


//std::vector<std::pair<std::string, std::vector<int>>> read_csv(std::string filename){
    // Reads a CSV file into a vector of <string, vector<int>> pairs where
    // each pair represents <column name, column values>



int main(){
    // Create a vector of <string, int vector> pairs to store the result
   // std::vector<string> result;
    std::vector<int> x_start;
    std::vector<int> x_end;
    std::vector<int> y_start;
    std::vector<int> y_end;

    // Create an input filestream
    std::ifstream myFile("data1.csv");

    // Make sure the file is open
    if(!myFile.is_open()) throw std::runtime_error("Could not open file");

    // Helper vars
    std::string line, colname;
    int val;

    // Read the column names
    if(myFile.good())
    {
        // Extract the first line in the file
        std::getline(myFile, line);
      
        // Create a stringstream from line
        std::stringstream ss(line);

        // Extract each column name
        while(std::getline(ss, colname, ',')){
            
            // Initialize and add <colname, int vector> pairs to result
           // result.push_back(colname);
           // std::cout << " COLUMN NAME "<< colname <<std::endl;


        }
    }

    // Read data, line by line
    while(std::getline(myFile, line))
    {
        // Create a stringstream of the current line
        std::stringstream ss(line);
        
        // Keep track of the current column index
        int colIdx = 0;
        if(colIdx == 1){
          for (int i=0; i<v.size();i++){
            std::cout << x_start[i] << std::endl;
          }      
        }
        
        
        // Extract each integer
        while(ss >> val){
            
            switch(colIdx){
                case 0:
                      // Add the current integer to the 'colIdx' column's values vector
                    x_start.push_back(val);

                    // If the next token is a comma, ignore it and move on
                    if(ss.peek() == ',') ss.ignore();
                      break;
                case 1:
                    y_start.push_back(val);

                      if(ss.peek() == ',') ss.ignore();
                        break;
                case 2:
                    x_end.push_back(val);

                      if(ss.peek() == ',') ss.ignore();
                        break;
                case 3:
                    y_end.push_back(val);

                      if(ss.peek() == ',') ss.ignore();
                        break;

                default: break;
              }
              
             
            
              // Increment the column index
             colIdx++;
        }
    }

    // Close file
    myFile.close();

    return 0;
}

//int main() {
    // Read three_cols.csv and ones.csv
    //std::vector<std::pair<std::string, std::vector<int>>> three_cols = read_csv("three_cols.csv");
   // std::vector<std::pair<std::string, std::vector<int>>> data = read_csv("data1.csv");

    // Write to another file to check that this was successful
    //write_csv("three_cols_copy.csv", three_cols);
    //write_csv("ones_copy.csv", ones);
    
  //  return 0;
//}
