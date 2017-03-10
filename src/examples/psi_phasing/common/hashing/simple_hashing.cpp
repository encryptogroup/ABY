/*
 * simple_hashing.cpp
 *
 *  Created on: Oct 8, 2014
 *      Author: mzohner
 */

#include "simple_hashing.h"

uint8_t* simple_hashing(uint8_t* elements, uint32_t neles, uint32_t bitlen, uint32_t *outbitlen, uint32_t* nelesinbin, uint32_t nbins,
		uint32_t* maxbinsize, uint32_t ntasks, uint32_t nhashfuns, prf_state_ctx* prf_state) {
	sht_ctx* table;
	//uint8_t** bin_content;
	uint8_t *eleptr, *bin_ptr, *result, *res_bins;
	uint32_t i, j, tmpneles;
	sheg_ctx* ctx;
	pthread_t* entry_gen_tasks;
	hs_t hs;

	init_hashing_state(&hs, neles, bitlen, nbins, nhashfuns, prf_state);
	//Set the output bit-length of the hashed elements
	*outbitlen = hs.outbitlen;

	entry_gen_tasks = (pthread_t*) malloc(sizeof(pthread_t) * ntasks);
	ctx = (sheg_ctx*) malloc(sizeof(sheg_ctx) * ntasks);
	table = (sht_ctx*) malloc(sizeof(sht_ctx) * ntasks);


	//in case no maxbinsize is specified, compute based on Eq3 in eprint 2016/930
	if(*maxbinsize == 0) {
		int maxbin = compute_maxbin(nhashfuns * neles, hs.nbins);
		assert(maxbin != -1);
		*maxbinsize = (uint32_t) maxbin;
	}

	for(i = 0; i < ntasks; i++) {
		init_hash_table(table + i, ceil_divide(neles, ntasks), &hs, *maxbinsize);
	}

	//for(i = 0; i < nbins; i++)
	//	pthread_mutex_init(locks+i, NULL);

	//tmpbuf = (uint8_t*) malloc(table->outbytelen);

	for(i = 0; i < ntasks; i++) {
		ctx[i].elements = elements;
		ctx[i].table = table + i;
		ctx[i].startpos = i * ceil_divide(neles, ntasks);
		ctx[i].endpos = min(ctx[i].startpos + ceil_divide(neles, ntasks), neles);
		ctx[i].hs = &hs;

		//cout << "Thread " << i << " starting from " << ctx[i].startpos << " going to " << ctx[i].endpos << " for " << neles << " elements" << endl;
		if(pthread_create(entry_gen_tasks+i, NULL, gen_entries, (void*) (ctx+i))) {
			cerr << "Error in creating new pthread at simple hashing!" << endl;
			exit(0);
		}
	}

	for(i = 0; i < ntasks; i++) {
		if(pthread_join(entry_gen_tasks[i], NULL)) {
			cerr << "Error in joining pthread at simple hashing!" << endl;
			exit(0);
		}
	}

	*maxbinsize = table->maxbinsize;

	//for(i = 0, eleptr=elements; i < neles; i++, eleptr+=inbytelen) {
	//	insert_element(table, eleptr, tmpbuf);
	//}

	//malloc and copy simple hash table into hash table
	//bin_content = (uint8_t**) malloc(sizeof(uint8_t*) * nbins);
	//*nelesinbin = (uint32_t*) malloc(sizeof(uint32_t) * nbins);

	res_bins = (uint8_t*) malloc(neles * hs.nhashfuns * hs.outbytelen);
	bin_ptr = res_bins;


	for(i = 0; i < hs.nbins; i++) {
		nelesinbin[i] = 0;
		for(j = 0; j < ntasks; j++) {
			tmpneles = (table +j)->bins[i].nvals;
			nelesinbin[i] += tmpneles;
			//bin_content[i] = (uint8_t*) malloc(nelesinbin[i] * table->outbytelen);
			memcpy(bin_ptr, (table + j)->bins[i].values, tmpneles * hs.outbytelen);
			bin_ptr += (tmpneles * hs.outbytelen);
		}
		//right now only the number of elements in each bin is copied instead of the max bin size
	}

	for(j = 0; j < ntasks; j++)
		free_hash_table(table + j);
	free(table);
	free(entry_gen_tasks);
	free(ctx);

	//for(i = 0; i < nbins; i++)
	//	pthread_mutex_destroy(locks+i);
	//free(locks);

	free_hashing_state(&hs);

	return res_bins;
}

void *gen_entries(void *ctx_tmp) {
	//Insert elements in parallel, use lock to communicate
	uint8_t *tmpbuf, *eleptr;
	sheg_ctx* ctx = (sheg_ctx*) ctx_tmp;
	uint32_t i, inbytelen, *address;

	address = (uint32_t*) malloc(ctx->hs->nhashfuns * sizeof(uint32_t));
	tmpbuf = (uint8_t*) calloc(ceil_divide(ctx->hs->outbitlen, 8), sizeof(uint8_t));	//for(i = 0; i < NUM_HASH_FUNCTIONS; i++) {
	//	tmpbuf[i] = (uint8_t*) malloc(ceil_divide(ctx->hs->outbitlen, 8));
	//}

	for(i = ctx->startpos, eleptr=ctx->elements, inbytelen=ctx->hs->inbytelen; i < ctx->endpos; i++, eleptr+=inbytelen) {
		insert_element(ctx->table, eleptr, address, tmpbuf, ctx->hs);
	}
	free(tmpbuf);
	free(address);
}

inline void insert_element(sht_ctx* table, uint8_t* element, uint32_t* address, uint8_t* tmpbuf, hs_t* hs) {
	uint32_t i, j;
	bin_ctx* tmp_bin;

	hashElement(element, address, tmpbuf, hs);

	//cout << "Element " <<
	for(i = 0; i < hs->nhashfuns; i++) {

		tmp_bin=table->bins + address[i];
		//pthread_mutex_lock(locks + address[i]);
		//cout << "Element: " << ((uint32_t*) tmpbuf)[0] << ", position = " << (i&0x03) << " , mapped to " << address[i] << endl;
		memcpy(tmp_bin->values + tmp_bin->nvals * hs->outbytelen, tmpbuf, hs->outbytelen);
		(tmp_bin->values + tmp_bin->nvals * hs->outbytelen)[0] ^= (i&0x03);
		/*for(j = 0; j < i; j++) {
			if(address[i] == address[j]) {
				memset(tmp_bin->values + tmp_bin->nvals * hs->outbytelen, DUMMY_ENTRY_SERVER, hs->outbytelen);
			}
		}*/
		tmp_bin->nvals++;

		if(tmp_bin->nvals == table->maxbinsize) {
			cout << "The hash table grew too big, increasing size!" << endl;
			increase_max_bin_size(table, hs->outbytelen);
		}
		//assert(tmp_bin->nvals < table->maxbinsize);
		/*cout << "Inserted into bin: " << address << ": " << (hex);
		for(uint32_t j = 0; j < table->outbytelen; j++) {
			cout << (unsigned int) tmpbuf[j];
		}
		cout << (dec) << endl;*/
		//pthread_mutex_unlock(locks + address[i]);
	}
}

void init_hash_table(sht_ctx* table, uint32_t nelements, hs_t* hs, uint32_t maxbinsize) {
	uint32_t i;

	table->nbins = hs->nbins;
	table->maxbinsize = maxbinsize;

	table->bins = (bin_ctx*) calloc(hs->nbins, sizeof(bin_ctx));

	for(i = 0; i < hs->nbins; i++) {
		table->bins[i].values = (uint8_t*) malloc(table->maxbinsize * hs->outbytelen);
	}
}

void free_hash_table(sht_ctx* table) {
	uint32_t i;
	//1. free the byte-pointers for the values in the bints
	for(i = 0; i < table->nbins; i++) {
		//if(table->bins[i].nvals > 0)
			free(table->bins[i].values);
	}
	//2. free the bins
	free(table->bins);
	//3. free the actual table
	//free(table);
}

inline uint32_t get_max_bin_size(uint32_t nbins, uint32_t neles) {
	double n = neles;
	if(ceil_divide(neles, nbins) < 3) {
		if(neles >= (1<<24))
			return 27;
		if(neles >= (1<<20))
			return 26;
		if(neles >= (1<<16))
			return 25;
		if(neles >= (1<<12))
			return 24;
		if(neles >= (1<<8))
			return 23;
	} else
		return 6*max((uint32_t) ceil_divide(neles, nbins), (uint32_t) 3);
}

void increase_max_bin_size(sht_ctx* table, uint32_t valbytelen) {
	uint32_t new_maxsize = table->maxbinsize * 2;
	uint8_t* tmpvals;
	for(uint32_t i = 0; i < table->nbins; i++) {
		tmpvals = table->bins[i].values;
		table->bins[i].values = (uint8_t*) malloc(new_maxsize * valbytelen);
		memcpy(table->bins[i].values, tmpvals, table->bins[i].nvals * valbytelen);
		free(tmpvals);
	}
	table->maxbinsize = new_maxsize;
}

//computes res = n choose k
void nchoosek_mul(mpf_t res, int n, int k) {
	mpf_t tmp;
	mpf_init(tmp);


	mpf_set_ui(tmp, 1);
	mpf_set_ui(res, 1);

	for(int i = 1; i <= k; i++) {
		mpf_set_ui(tmp, n - (k - i));
		mpf_div_ui(tmp, tmp, i);
		mpf_mul(res, res, tmp);
	}

	mpf_clear(tmp);
}


//computes the number of maximum balls in a bin using the EQ3 in eprint 2016/930.
//first argument: number of balls, n, second argument: number of bins
int compute_maxbin(uint32_t balls_int, uint32_t bins_int) {

	//cout << "Computing parameters for balls = " << balls_int << ", and bins = " << bins_int << endl;

	mpf_set_default_prec(1024);

	int neg_40 = 40;
	int maxbin = -1;

	mpf_t b, p, pinv, cmb, p1, p2, sum, tmp, p40, two;
	mpf_init(b);
	mpf_init(p);
	mpf_init(p1);
	mpf_init(p2);
	mpf_init(pinv);
	mpf_init(cmb);
	mpf_init(sum);
	mpf_init(tmp);
	mpf_init(p40);
	mpf_init(two);

	mpf_set_d(two, (double) 0.5);

	mpf_pow_ui(p40, two, neg_40);

	//Set the number of elements and the number of bins
	mpf_set_ui(b, bins_int);

	//Compute the probability of mapping to a bin as well as its inverse
	mpf_ui_div(p, 1L, b);
	mpf_ui_sub(pinv, 1L, p);

	mpf_set_ui(sum, 0);

	bool gotp40=false;

	for(int i = 0; i < 150000 && !gotp40; i++) {
		nchoosek_mul(cmb, balls_int, i);

		//(1/b)^i
		mpf_pow_ui(p1, p, i);

		//(1-1/b)^(n-i)
		mpf_pow_ui(p2, pinv, balls_int-i);

		//cmb * p1 * p2 * b
		mpf_mul(tmp, cmb, p1);
		mpf_mul(tmp, tmp, p2);
		mpf_add(sum, sum, tmp);

		mpf_pow_ui(tmp, sum, bins_int);
		mpf_ui_sub(tmp, 1, tmp);

		if(mpf_cmp(tmp, p40) < 1  && !gotp40) {
			maxbin = i;
			//cout << ", 2^-{40}: " << i << endl;
			gotp40=true;
		}
	}

	mpf_clear(b);
	mpf_clear(p);
	mpf_clear(p1);
	mpf_clear(p2);
	mpf_clear(pinv);
	mpf_clear(cmb);
	mpf_clear(sum);
	mpf_clear(tmp);
	mpf_clear(p40);
	mpf_clear(two);

	//cout << "Resulting maxbin = " << maxbin << endl;

	return maxbin;
}




