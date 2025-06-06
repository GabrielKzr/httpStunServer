#ifndef FIREBASE_API_HPP
#define FIREBASE_API_HPP

#include "FirebaseManager.hpp"

class FirebaseApi {

    private:

        FirebaseManager* firebaseManager;

    public:

        bool addRouterToUser(const std::string& uid, const std::string& routerUuid, bool status);
        bool removeRouterFromUser(const std::string& localId, const std::string& uuid);

        bool clientHasUuid(const std::string& uuid, const std::string& idToken);

        bool addDeviceToUser(const std::string& uid, const std::string& deviceToken);
        bool removeDeviceFromUser(const std::string& uid, const std::string& deviceToken);
        bool userHasDevice(const std::string& uid, const std::string& deviceToken);

        FirebaseApi(std::string project_id, std::string api_key, std::string pathToAdmJson);

        ~FirebaseApi();
};

#endif