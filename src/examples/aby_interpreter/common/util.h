/**
 * @file util.h
 *
 * @brief This file contains utility functions for the ABY interpreter   
 *
 */

/** Split string by spaces
*
* @param str input string 
*
* @return vector of substrings split by spaces 
*/
std::vector<std::string> split_(std::string str) {
    std::vector<std::string> result;
    std::istringstream ss(str);
    std::string word; 
    while (ss >> word) {
        result.push_back(word);
    }
    return result;
}
