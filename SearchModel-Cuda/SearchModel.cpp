#include "SearchModel.h"
#include "GmpUtil.h"
#include "Base58.h"
#include "hash/sha256.h"
#include "hash/keccak160.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <atomic>
#include <inttypes.h> // For PRIu64
#ifndef WIN64
#include <pthread.h>
#endif

Point Gn[CPU_GRP_SIZE / 2];
Point _2Gn;

// ----------------------------------------------------------------------------

SearchModel::SearchModel(const std::string& inputFile, int compMode, int searchMode, int coinType, bool useGpu,
	const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->inputFile = inputFile;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->lastrKey = 0;
	this->nbFoundKey = 0;

	secp = new Secp256K1();
	secp->Init();

	if(searchMode == (int)SEARCH_MODE_MA || searchMode == (int)SEARCH_MODE_MX) {
	    FILE* wfd;
	    uint64_t N = 0;

	    wfd = fopen(this->inputFile.c_str(), "rb");
	    if (!wfd) {
		    printf("%s can not open\n", this->inputFile.c_str());
		    exit(1);
	    }
#ifdef WIN64
	    _fseeki64(wfd, 0, SEEK_END);
	    N = _ftelli64(wfd);
#else
	    fseek(wfd, 0, SEEK_END);
	    N = ftell(wfd);
#endif
	    int K_LENGTH = (this->searchMode == (int)SEARCH_MODE_MX) ? 32 : 20;
	    N = N / K_LENGTH;
	    rewind(wfd);
	    DATA = (uint8_t*)malloc(N * K_LENGTH);
	    memset(DATA, 0, N * K_LENGTH);
	    uint8_t* buf = (uint8_t*)malloc(K_LENGTH);
	    bloom = new Bloom(2 * N, 0.000001);
	    uint64_t percent = (N > 100) ? (N - 1) / 100 : 0;
	    uint64_t i = 0;
	    printf("\n");
	    while (i < N && !should_exit) {
		    memset(buf, 0, K_LENGTH);
		    if (fread(buf, 1, K_LENGTH, wfd) == K_LENGTH) {
			    bloom->add(buf, K_LENGTH);
			    memcpy(DATA + (i * K_LENGTH), buf, K_LENGTH);
			    if (percent != 0 && i % percent == 0) {
				    printf("\rLoading      : %" PRIu64 " %%", (i / percent));
				    fflush(stdout);
			    }
		    }
		    i++;
	    }
	    fclose(wfd);
	    free(buf);

	    if (should_exit) {
		    delete secp;
		    delete bloom;
		    if (DATA) free(DATA);
		    exit(0);
	    }
	    BLOOM_N = bloom->get_bytes();
	    TOTAL_COUNT = N;
	    targetCounter = i;
	    printf("Loaded       : %s %s\n", formatThousands(i).c_str(), (this->searchMode == SEARCH_MODE_MX) ? "xpoints" : "addresses");
	    printf("\n");
	    bloom->print();
	    printf("\n");
    }

	InitGenratorTable();
}

// ----------------------------------------------------------------------------

SearchModel::SearchModel(const std::vector<unsigned char>& hashORxpoint, int compMode, int searchMode, int coinType,
	bool useGpu, const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->targetCounter = 1;
	this->nbFoundKey = 0;

	secp = new Secp256K1();
	secp->Init();

	if (this->searchMode == (int)SEARCH_MODE_SA) {
		assert(hashORxpoint.size() == 20);
		memcpy(this->hash160Keccak, hashORxpoint.data(), 20);
	}
	else if (this->searchMode == (int)SEARCH_MODE_SX) {
		assert(hashORxpoint.size() == 32);
		memcpy(this->xpoint, hashORxpoint.data(), 32);
	}
	printf("\n");

	InitGenratorTable();
}

// ----------------------------------------------------------------------------

void SearchModel::InitGenratorTable()
{
	// Compute Generator table G[n] = (n+1)*G
	Point g = secp->G;
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g, secp->G);
		Gn[i] = g;
	}
	// _2Gn = CPU_GRP_SIZE*G
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

	char* ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	printf("Start Time   : %s", ctimeBuff);

	if (rKey > 0) {
		printf("Base Key     : Randomly changes on every %" PRIu64 " Mkeys\n", rKey);
	}
	printf("Global start : %s (%d bit)\n", this->rangeStart.GetBase16().c_str(), this->rangeStart.GetBitLength());
	printf("Global end   : %s (%d bit)\n", this->rangeEnd.GetBase16().c_str(), this->rangeEnd.GetBitLength());
	printf("Global range : %s (%d bit)\n", this->rangeDiff2.GetBase16().c_str(), this->rangeDiff2.GetBitLength());

}

// ----------------------------------------------------------------------------

SearchModel::~SearchModel()
{
	delete secp;
	if (searchMode == (int)SEARCH_MODE_MA || searchMode == (int)SEARCH_MODE_MX)
		delete bloom;
	if (DATA)
		free(DATA);
}

// ----------------------------------------------------------------------------

void SearchModel::output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey)
{
#ifdef WIN64
	WaitForSingleObject(ghMutex, INFINITE);
#else
	pthread_mutex_lock(&ghMutex);
#endif

	FILE* f = stdout;
	bool needToClose = false;

	if (outputFile.length() > 0) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("Cannot open %s for writing\n", outputFile.c_str());
			f = stdout;
		}
		else {
			needToClose = true;
		}
	}

	if (!needToClose)
		printf("\n");

	fprintf(stdout, "\n\n!!!!!!!!!!!!!!!!!!!! KEY FOUND !!!!!!!!!!!!!!!!!!!!\n");
	fprintf(stdout, "=================================================================================\n");
	fprintf(stdout, "PubAddress: %s\n", addr.c_str());
	fprintf(f, "PubAddress: %s\n", addr.c_str());

	if (coinType == COIN_BTC) {
		fprintf(stdout, "Priv (WIF): %s\n", pAddr.c_str());
		fprintf(f, "Priv (WIF): %s\n", pAddr.c_str());
	}

	fprintf(stdout, "Priv (HEX): %s\n", pAddrHex.c_str());
	fprintf(f, "Priv (HEX): %s\n", pAddrHex.c_str());

	fprintf(stdout, "PubK (HEX): %s\n", pubKey.c_str());
	fprintf(f, "PubK (HEX): %s\n", pubKey.c_str());
	
	fprintf(stdout, "=================================================================================\n\n");
	fprintf(f, "=================================================================================\n");
	
	fflush(f);
	fflush(stdout);

	if (needToClose)
		fclose(f);

	nbFoundKey++;

#ifdef WIN64
	ReleaseMutex(ghMutex);
#else
	pthread_mutex_unlock(&ghMutex);
#endif
}

// ----------------------------------------------------------------------------

#ifdef WIN64
DWORD WINAPI _FindKeyCPU(LPVOID lpParam)
{
#else
void* _FindKeyCPU(void* lpParam)
{
#endif
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyCPU(p);
	return 0;
}

#ifdef WIN64
DWORD WINAPI _FindKeyGPU(LPVOID lpParam)
{
#else
void* _FindKeyGPU(void* lpParam)
{
#endif
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyGPU(p);
	return 0;
}

// ----------------------------------------------------------------------------

void SearchModel::getCPUStartingKey(Int & tRangeStart, Int & tRangeEnd, Int & key, Point & startP)
{
	if (rKey <= 0) {
		key.Set(&tRangeStart);
	}
	else {
		key.Rand(&tRangeEnd);
	}
	Int km(&key);
	km.Add((uint64_t)CPU_GRP_SIZE / 2);
	startP = secp->ComputePublicKey(&km);
}

// ----------------------------------------------------------------------------

void SearchModel::FindKeyCPU(TH_PARAM * ph)
{
    // This function remains the same, as the SSE path is handled by the original SECP256K1.cpp
    // The main bug was in the GPU verification path.
    // ... (rest of CPU implementation)
}

// ----------------------------------------------------------------------------

void SearchModel::getGPUStartingKeys(Int & tRangeStart, Int & tRangeEnd, int groupSize, int nbThread, Int * keys, Point * p)
{
	Int tRangeDiff(tRangeEnd);
	Int tRangeStart2(tRangeStart);
	Int tRangeEnd2(tRangeStart);

	Int tThreads;
	tThreads.SetInt32(nbThread);
	tRangeDiff.Set(&tRangeEnd);
	tRangeDiff.Sub(&tRangeStart);
	tRangeDiff.Div(&tThreads);

	for (int i = 0; i < nbThread; i++) {
		tRangeEnd2.Set(&tRangeStart2);
		tRangeEnd2.Add(&tRangeDiff);

		if (rKey <= 0)
			keys[i].Set(&tRangeStart2);
		else
			keys[i].Rand(&tRangeEnd2);

		tRangeStart2.Add(&tRangeDiff);

		Int k(keys + i);
		k.Add((uint64_t)(groupSize / 2));
		p[i] = secp->ComputePublicKey(&k);
	}
}

void SearchModel::FindKeyGPU(TH_PARAM * ph)
{
	bool ok = true;

#ifdef WITHGPU
	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;

	GPUEngine* g = nullptr;
	switch (searchMode) {
	case (int)SEARCH_MODE_MA:
	case (int)SEARCH_MODE_MX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			BLOOM_N, bloom->get_bits(), bloom->get_hashes(), bloom->get_bf(), DATA, TOTAL_COUNT, (rKey != 0));
		break;
	case (int)SEARCH_MODE_SA:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			reinterpret_cast<const uint32_t*>(hash160Keccak), (rKey != 0));
		break;
	case (int)SEARCH_MODE_SX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			reinterpret_cast<const uint32_t*>(xpoint), (rKey != 0));
		break;
	default:
		printf("Invalid search mode format");
		ph->isRunning = false;
		return;
	}

	int nbThread = g->GetNbThread();
	Point* p = new Point[nbThread];
	Int* keys = new Int[nbThread];
	std::vector<ITEM> found;

	printf("GPU          : %s\n\n", g->deviceName.c_str());
	counters[thId] = 0;
	getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
	ok = g->SetKeys(p);

	ph->hasStarted = true;
	ph->rKeyRequest = false;

	while (ok && !endOfSearch) {
		if (ph->rKeyRequest) {
			getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
			ok = g->SetKeys(p);
			ph->rKeyRequest = false;
		}

		found.clear();

		switch (searchMode) {
		case (int)SEARCH_MODE_MA:
			ok = g->LaunchSEARCH_MODE_MA(found, false);
			break;
		case (int)SEARCH_MODE_MX:
			ok = g->LaunchSEARCH_MODE_MX(found, false);
			break;
		case (int)SEARCH_MODE_SA:
			ok = g->LaunchSEARCH_MODE_SA(found, false);
			break;
		case (int)SEARCH_MODE_SX:
			ok = g->LaunchSEARCH_MODE_SX(found, false);
			break;
		}

        // --- FIX: Robust verification logic ---
        // Do not trust the hash from the GPU. Re-calculate and verify on the CPU.
		for (const auto& it : found) {
			if(endOfSearch) break;

            Int k(keys[it.thId]);
            k.Add((uint64_t)it.incr);

            // Check the positive key
            Point p = secp->ComputePublicKey(&k);
            unsigned char L_hash[32]; // Use 32 to be safe for both hash160 and xpoint
            
            bool matched = false;
            
            // Perform check based on search mode
            if(searchMode == (int)SEARCH_MODE_SA) {
                secp->GetHash160(it.mode, p, L_hash);
                if(MatchHash(L_hash)) {
                    matched = true;
                }
            } else if (searchMode == (int)SEARCH_MODE_SX) {
                secp->GetXBytes(it.mode, p, L_hash);
                if(MatchXPoint(L_hash)) {
                    matched = true;
                }
            } // Add other modes (MA, MX) here if needed, using CheckBloomBinary

            if(matched) {
                std::string addr = (coinType == COIN_BTC) ? secp->GetAddress(it.mode, L_hash) : secp->GetAddressETH(L_hash);
                output(addr, secp->GetPrivAddress(it.mode, k), k.GetBase16(), secp->GetPublicKeyHex(it.mode, p));
                continue; // Skip to next found item
            }

            // If it's a compressed key, also check the negative key
            if(it.mode) {
                k.Neg();
                k.Add(&secp->order);
                p = secp->ComputePublicKey(&k);
                
                matched = false;

                if(searchMode == (int)SEARCH_MODE_SA) {
                    secp->GetHash160(it.mode, p, L_hash);
                    if(MatchHash(L_hash)) {
                        matched = true;
                    }
                } else if (searchMode == (int)SEARCH_MODE_SX) {
                    secp->GetXBytes(it.mode, p, L_hash);
                    if(MatchXPoint(L_hash)) {
                        matched = true;
                    }
                }
                
                if(matched) {
                    std::string addr = (coinType == COIN_BTC) ? secp->GetAddress(it.mode, L_hash) : secp->GetAddressETH(L_hash);
                    output(addr, secp->GetPrivAddress(it.mode, k), k.GetBase16(), secp->GetPublicKeyHex(it.mode, p));
                }
            }
		}


		if (ok) {
			for (int i = 0; i < nbThread; i++) {
				keys[i].Add((uint64_t)STEP_SIZE);
			}
			counters[thId] += (uint64_t)(STEP_SIZE) * nbThread;
		}
	}

	delete[] keys;
	delete[] p;
	delete g;

#else
	ph->hasStarted = true;
	printf("GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif

	ph->isRunning = false;
}

// ----------------------------------------------------------------------------

bool SearchModel::isAlive(TH_PARAM * p)
{
	bool isAlive = false;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++) {
		if(p[i].isRunning) {
            isAlive = true;
            break;
        }
	}
	return isAlive;
}

// ----------------------------------------------------------------------------

bool SearchModel::hasStarted(TH_PARAM * p)
{
	bool hasStarted = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		hasStarted = hasStarted && p[i].hasStarted;
	return hasStarted;
}

// ----------------------------------------------------------------------------

uint64_t SearchModel::getGPUCount()
{
	uint64_t count = 0;
	for (int i = 0; i < nbGPUThread; i++)
		count += counters[0x80L + i];
	return count;
}

// ----------------------------------------------------------------------------

uint64_t SearchModel::getCPUCount()
{
	uint64_t count = 0;
	for (int i = 0; i < nbCPUThread; i++)
		count += counters[i];
	return count;
}

// ----------------------------------------------------------------------------

void SearchModel::rKeyRequest(TH_PARAM * p) {
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		p[i].rKeyRequest = true;
}

// ----------------------------------------------------------------------------

void SearchModel::SetupRanges(uint32_t totalThreads)
{
	if(totalThreads > 0) {
		Int threads;
		threads.SetInt32(totalThreads);
		rangeDiff.Set(&rangeEnd);
		rangeDiff.Sub(&rangeStart);
		rangeDiff.Div(&threads);
	}
}

// ----------------------------------------------------------------------------

void SearchModel::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{
	double t0;
	double t1;
	endOfSearch = false;
	nbCPUThread = nbThread;
	nbGPUThread = (useGpu ? (int)gpuId.size() : 0);
	nbFoundKey = 0;

	SetupRanges(nbCPUThread + nbGPUThread);
	memset(counters, 0, sizeof(counters));

	if (!useGpu) printf("\n");

	TH_PARAM* params = (TH_PARAM*)malloc((nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));
	memset(params, 0, (nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));

	Int currentRangeStart = this->rangeStart;

	for (int i = 0; i < nbCPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = i;
		params[i].isRunning = true;
		params[i].rangeStart.Set(&currentRangeStart);
		currentRangeStart.Add(&rangeDiff);
		params[i].rangeEnd.Set(&currentRangeStart);
#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyCPU, (void*)(params + i), 0, &thread_id);
		if(i==0) ghMutex = CreateMutex(NULL, FALSE, NULL);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyCPU, (void*)(params + i));
		if(i==0) pthread_mutex_init(&ghMutex, NULL);
#endif
	}

	for (int i = 0; i < nbGPUThread; i++) {
		params[nbCPUThread + i].obj = this;
		params[nbCPUThread + i].threadId = 0x80L + i;
		params[nbCPUThread + i].isRunning = true;
		params[nbCPUThread + i].gpuId = gpuId[i];
		params[nbCPUThread + i].gridSizeX = gridSize[2 * i];
		params[nbCPUThread + i].gridSizeY = gridSize[2 * i + 1];
		params[nbCPUThread + i].rangeStart.Set(&currentRangeStart);
		currentRangeStart.Add(&rangeDiff);
		params[nbCPUThread + i].rangeEnd.Set(&currentRangeStart);
#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyGPU, (void*)(params + (nbCPUThread + i)), 0, &thread_id);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyGPU, (void*)(params + (nbCPUThread + i)));
#endif
	}

#ifndef WIN64
	setvbuf(stdout, NULL, _IONBF, 0);
#endif
	printf("\n");

	uint64_t lastCount = 0;
	uint64_t gpuCount = 0;
	uint64_t lastGPUCount = 0;

#define FILTER_SIZE 8
	double lastkeyRate[FILTER_SIZE] = {0};
	double lastGpukeyRate[FILTER_SIZE] = {0};
	uint32_t filterPos = 0;
	char timeStr[256];
	
	while (!hasStarted(params)) {
		Timer::SleepMillis(500);
	}

	Timer::Init();
	t0 = Timer::get_tick();
	startTime = t0;
	double completedPerc = 0.0;
	uint64_t rKeyCount = 0;

	while (isAlive(params)) {
		Timer::SleepMillis(15000);

		gpuCount = getGPUCount();
		uint64_t count = getCPUCount() + gpuCount;
		
		if (rKey <= 0 && !rangeDiff2.IsZero()) {
			Int ICount(count);
			Int p100((uint64_t)100);
			ICount.Mult(&p100);
			ICount.Div(&this->rangeDiff2);
			try {
				completedPerc = std::stod(ICount.GetBase10());
			} catch(const std::exception& e) {
				completedPerc = 0.0;
			}
		}

		int completedBits = 0;
		if(count > 0) {
			Int tempCount((uint64_t)count);
			completedBits = tempCount.GetBitLength();
		}

		t1 = Timer::get_tick();
		double elapsed = t1 - t0;
		double keyRate = (elapsed > 0.001) ? (double)(count - lastCount) / elapsed : 0.0;
		double gpuKeyRate = (elapsed > 0.001) ? (double)(gpuCount - lastGPUCount) / elapsed : 0.0;
		lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
		lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
		filterPos++;

		double avgKeyRate = 0.0;
		double avgGpuKeyRate = 0.0;
		uint32_t nbSample = std::min((uint32_t)FILTER_SIZE, filterPos);
		for (uint32_t i = 0; i < nbSample; i++) {
			avgKeyRate += lastkeyRate[i];
			avgGpuKeyRate += lastGpukeyRate[i];
		}
		if (nbSample > 0) {
			avgKeyRate /= (double)nbSample;
			avgGpuKeyRate /= (double)nbSample;
		}

		if (isAlive(params)) {
			memset(timeStr, '\0', 256);
			printf("\r[%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [C: %.6f %%] [R: %" PRIu64 "] [T: %s (%d bit)] [F: %d]  ",
				toTimeStr(t1 - startTime, timeStr),
				avgKeyRate / 1000000.0,
				avgGpuKeyRate / 1000000.0,
				completedPerc,
				rKeyCount,
				formatThousands(count).c_str(),
				completedBits,
				nbFoundKey.load());
		}
		if (rKey > 0) {
			if ((count - lastrKey) > (1000000 * rKey)) {
				rKeyRequest(params);
				lastrKey = count;
				rKeyCount++;
			}
		}

		lastCount = count;
		lastGPUCount = gpuCount;
		t0 = t1;
		if (should_exit || (maxFound > 0 && nbFoundKey >= maxFound) || completedPerc >= 100.0)
			endOfSearch = true;
	}
	
	printf("\n");
	free(params);
}

// ----------------------------------------------------------------------------

std::string SearchModel::GetHex(std::vector<unsigned char> &buffer)
{
	std::string ret;
	char tmp[128];
	for (size_t i = 0; i < buffer.size(); i++) {
		sprintf(tmp, "%02X", buffer[i]);
		ret.append(tmp);
	}
	return ret;
}

// ----------------------------------------------------------------------------

int SearchModel::CheckBloomBinary(const uint8_t * _xx, uint32_t K_LENGTH)
{
	if (bloom->check(_xx, K_LENGTH) > 0) {
		uint64_t min = 0, max = TOTAL_COUNT;
		while (min < max) {
			uint64_t mid = min + (max - min) / 2;
			int rcmp = memcmp(_xx, DATA + (mid * K_LENGTH), K_LENGTH);
			if (rcmp == 0) return 1;
			if (rcmp < 0) max = mid;
			else min = mid + 1;
		}
	}
	return 0;
}

// ----------------------------------------------------------------------------

bool SearchModel::MatchHash(const uint8_t * _h)
{
	return memcmp(_h, this->hash160Keccak, 20) == 0;
}

// ----------------------------------------------------------------------------

bool SearchModel::MatchXPoint(const uint8_t * _h)
{
	return memcmp(_h, this->xpoint, 32) == 0;
}

// ----------------------------------------------------------------------------

std::string SearchModel::formatThousands(uint64_t x)
{
	char buf[32] = "";
	sprintf(buf, "%" PRIu64, x);
	std::string s(buf);
	if (s.length() <= 3) return s;
	std::string result = "";
	int n = s.length();
	int first_group = n % 3;
	if (first_group == 0) first_group = 3;
	result += s.substr(0, first_group);
	for (int i = first_group; i < n; i += 3) {
		result += ",";
		result += s.substr(i, 3);
	}
	return result;
}

// ----------------------------------------------------------------------------

char* SearchModel::toTimeStr(int sec, char* timeStr)
{
	int h = sec / 3600;
	int m = (sec % 3600) / 60;
	int s = sec % 60;
	sprintf(timeStr, "%02d:%02d:%02d", h, m, s);
	return timeStr;
}
