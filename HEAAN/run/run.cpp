/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/

#include "../src/HEAAN.h"
#include "../src/Ring2Utils.h"
#include "math.h"

using namespace std;
using namespace NTL;

int main() {
	long logN = 14;
	long logQ = 160;
	long logp = 40;
	long logSlots = logN-1;
	Context context(logN, logQ);
	SecretKey secretKey(logN, (1<<logN)*2/3);
//	SecretKey secretKey(logN);
	Scheme scheme(secretKey, context);

	long slots = (1 << logSlots);
#if 1
  complex<double>* mvec1 = EvaluatorUtils::randomCircleArray(slots);
  complex<double>* mvec2 = EvaluatorUtils::randomCircleArray(slots);
  complex<double>* mvec3 = EvaluatorUtils::randomCircleArray(slots);
  complex<double>* mvec4 = EvaluatorUtils::randomCircleArray(slots);
	complex<double>* mvec = new complex<double>[slots];
	for(long i = 0; i < slots; i++) {
		mvec[i] = mvec1[i] * mvec2[i] * mvec3[i] * mvec4[i];
	}
#else
	complex<double>* mvec = EvaluatorUtils::randomCircleArray(slots);
#endif

#if 0
	ZZX exkey, axkey, bxkey;

	NumUtils::sampleUniform2(axkey, context.N, logQ);
	NumUtils::sampleGauss(exkey, context.N, context.sigma);
	Ring2Utils::mult(bxkey, secretKey.sx, axkey, context.Q, context.N);
	Ring2Utils::sub(bxkey, exkey, bxkey, context.Q, context.N);

	ZZX mx1 = context.encode(mvec1, slots, logp);
  ZZX mx2 = context.encode(mvec2, slots, logp);
  ZZX mx3 = context.encode(mvec3, slots, logp);
  ZZX mx4 = context.encode(mvec4, slots, logp);

  Plaintext msg1(mx1, logp, logQ, slots, false);
  Plaintext msg2(mx2, logp, logQ, slots, false);
  Plaintext msg3(mx3, logp, logQ, slots, false);
  Plaintext msg4(mx4, logp, logQ, slots, false);

	ZZX ax1, bx1, vx1, ex1;

	NumUtils::sampleZO(vx1, context.N);
	Ring2Utils::mult(ax1, vx1, axkey, context.Q, context.N);
	NumUtils::sampleGauss(ex1, context.N, context.sigma);
	Ring2Utils::addAndEqual(ax1, ex1, context.Q, context.N);

	Ring2Utils::mult(bx1, vx1, bxkey, context.Q, context.N);
	NumUtils::sampleGauss(ex1, context.N, context.sigma);
	Ring2Utils::addAndEqual(bx1, ex1, context.Q, context.N);
	Ring2Utils::addAndEqual(bx1, mx1, context.Q, context.N);

	Ciphertext cipher1(ax1, bx1, logp, logQ, slots, true);

	ZZX ax2, bx2, vx2, ex2;

	NumUtils::sampleZO(vx2, context.N);
	Ring2Utils::mult(ax2, vx2, axkey, context.Q, context.N);
	NumUtils::sampleGauss(ex2, context.N, context.sigma);
	Ring2Utils::addAndEqual(ax2, ex2, context.Q, context.N);

	Ring2Utils::mult(bx2, vx2, bxkey, context.Q, context.N);
	NumUtils::sampleGauss(ex2, context.N, context.sigma);
	Ring2Utils::addAndEqual(bx2, ex2, context.Q, context.N);
	Ring2Utils::addAndEqual(bx2, mx2, context.Q, context.N);

	Ciphertext cipher2(ax2, bx2, logp, logQ, slots, true);

  ZZX ax3, bx3, vx3, ex3;

  NumUtils::sampleZO(vx3, context.N);
  Ring2Utils::mult(ax3, vx3, axkey, context.Q, context.N);
  NumUtils::sampleGauss(ex3, context.N, context.sigma);
  Ring2Utils::addAndEqual(ax3, ex3, context.Q, context.N);

  Ring2Utils::mult(bx3, vx3, bxkey, context.Q, context.N);
  NumUtils::sampleGauss(ex3, context.N, context.sigma);
  Ring2Utils::addAndEqual(bx3, ex3, context.Q, context.N);
  Ring2Utils::addAndEqual(bx3, mx3, context.Q, context.N);

  Ciphertext cipher3(ax3, bx3, logp, logQ, slots, true);

  ZZX ax4, bx4, vx4, ex4;

  NumUtils::sampleZO(vx4, context.N);
  Ring2Utils::mult(ax4, vx4, axkey, context.Q, context.N);
  NumUtils::sampleGauss(ex4, context.N, context.sigma);
  Ring2Utils::addAndEqual(ax4, ex4, context.Q, context.N);

  Ring2Utils::mult(bx4, vx4, bxkey, context.Q, context.N);
  NumUtils::sampleGauss(ex4, context.N, context.sigma);
  Ring2Utils::addAndEqual(bx4, ex4, context.Q, context.N);
  Ring2Utils::addAndEqual(bx4, mx4, context.Q, context.N);

  Ciphertext cipher4(ax4, bx4, logp, logQ, slots, true);

#else

//	Ciphertext cipher = scheme.encrypt(mvec, slots, logp, logQ);

	Ciphertext cipher1 = scheme.encrypt(mvec1, slots, logp, logQ);
	Ciphertext cipher2 = scheme.encrypt(mvec2, slots, logp, logQ);
  Ciphertext cipher3 = scheme.encrypt(mvec3, slots, logp, logQ);
  Ciphertext cipher4 = scheme.encrypt(mvec4, slots, logp, logQ);

#endif
  Ciphertext cipher12 = scheme.mult(cipher1, cipher2);
  Ciphertext cipher34 = scheme.mult(cipher3, cipher4);
  scheme.reScaleByAndEqual(cipher12, logp);
  scheme.reScaleByAndEqual(cipher34, logp);
  Ciphertext cipher = scheme.mult(cipher12, cipher34);
  scheme.reScaleByAndEqual(cipher, logp);
	complex<double>* dvec = scheme.decrypt(secretKey, cipher);

	vector<double> diffvec(slots);
	double avg = 0.0;
	for (long i = 0; i < slots; ++i) {
		diffvec[i] = sqrt(pow(abs(mvec[i].real() - dvec[i].real()), 2) +
	                      pow(abs(mvec[i].imag() - dvec[i].imag()), 2));
	    avg += diffvec[i];
	}
	avg /= static_cast<double>(slots);
	double log2avg = log2(avg);
	std::cerr << -round(log2avg * 10) / 10 << std::endl;
	return 0;
}
