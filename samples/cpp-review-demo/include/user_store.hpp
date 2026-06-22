#pragma once

#include <string>
#include <vector>

struct UserRecord {
    std::string name;
    std::vector<int> scores;
};

int load_user_score(const UserRecord& user, int index);

