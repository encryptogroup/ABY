/**
 * @file util.h
 *
 * @brief This file contains utility functions for the ABY interpreter   
 *
 */

/** Split string by delimiter
*
* @param str input string 
* @param delimiter delimiter string
*
* @return vector of substrings split by delimiter 
*/
std::vector<std::string> split(std::string str, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = str.find (delimiter, pos_start)) != std::string::npos) {
        token = str.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        if (token.length() > 0) {
            res.push_back(token);
        }
    }
    
    token = str.substr(pos_start);
    if (token.length() > 0) {
        res.push_back(token);
    }
    return res;
}

/** Get path
*
* @param path path string
* @param suffix path suffix
*
* @return full path string
*/
std::string get_path(std::string path, std::string suffix) {
    auto path_list = split(path, "/");
    auto filename = path_list[path_list.size() - 1];
    path = path + "/" + filename + suffix;
    return path;
}
